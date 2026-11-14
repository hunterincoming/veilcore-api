# Rotating the backup key after the purge

**Why.** Every off-site backup is encrypted to the operator's backup key (README, "Off-site
backups"). Backups taken before records were sealed, and before the purge
(`scripts/purge-plaintext.mjs`), hold every record in plain text. They are object-locked, so
nobody can delete them early, and whoever has the private key can open them. Until that key
is gone, "VeilCore can't read your records" is not true of those backups.

The fix: make a new key, send new backups to it, check one, then destroy the old private
key. The old backups stay in the bucket until their lock runs out, but nobody can open them.

**Rules while doing this.**

- Never paste a private key (`AGE-SECRET-KEY-...`) into Railway, a chat, an email, a
  ticket or a terminal command line. Only the public key (`age1...`) goes into Railway.
- The steps below never print a private key or the operator token on screen.
- Do it in one sitting if you can. It takes about 30 minutes.

**What you need:** your computer with `age` (`brew install age`), the password manager,
the Railway dashboard, the Backblaze bucket page, and the operator token (in the password
manager).

## 1. Before you start

1. The purge has been run with `--apply --vacuum` on the live database, in a maintenance
   window (README, "The purge": the rebuild locks the whole file, and the server's requests
   fail while it runs), and the app still shows people their records.
2. Destroying the old key (step 6) also destroys your way back to before the purge: the
   only copies from before it are the backups the old key opens. Only go on once you are
   sure the purge went right.

## 2. Make the new key

In Terminal on your own computer (not on Railway):

```
mkdir -m 700 ~/veilcore-key-tmp
age-keygen -o ~/veilcore-key-tmp/new-backup-key.txt
```

It prints one line, `Public key: age1...`. That is the **public** key; it is safe to copy.
The private key is only in the file. Now:

1. Open the file (`open -e ~/veilcore-key-tmp/new-backup-key.txt`), copy all of it into a
   **new** password manager item named e.g. "VeilCore backup key (from <today's date>)".
   Keep the old item for now.
2. Delete the file and the folder:

   ```
   rm -r ~/veilcore-key-tmp
   ```

Lose the new private key and the new backups can't be opened by anyone, so check the
password manager item saved before you delete the file.

## 3. Point the registry at the new key

1. Railway, service `veilcore-api`, Variables: set `BACKUP_AGE_RECIPIENT` to the new
   `age1...` public key. Deploy.
2. Work out the new key's short id (the public key only):

   ```
   printf %s 'age1...the new public key...' | shasum -a 256 | cut -c1-12
   ```

3. In the deploy log, the line `backup: on, to ..., sealed to key <id>, ...` must show that
   id. If it shows `BACKUP: ... not a valid age public key`, the key was copied wrongly: fix
   the variable and deploy again.

## 4. Take a fresh backup now

The operator token is read without showing it, and passed to `curl` on its standard input
so it is not on the command line:

```
read -rs VEILCORE_OPERATOR_TOKEN     # paste the token, press Enter (nothing shows)
printf 'x-operator-token: %s\n' "$VEILCORE_OPERATOR_TOKEN" \
  | curl -sS -X POST -H @- https://veilcore-api-production.up.railway.app/admin/backup
```

The answer is `{"ok":true,"object":".../<time>.key-<id>.sqlite.gz.age","records":...}`. The
`key-<id>` must be the new id from step 3. (For the test registry, use its address instead.)

Check the status says the same:

```
printf 'x-operator-token: %s\n' "$VEILCORE_OPERATOR_TOKEN" \
  | curl -sS -H @- https://veilcore-api-production.up.railway.app/admin/backup
unset VEILCORE_OPERATOR_TOKEN
```

`recipientId` is the new id, `lastError` is `null`.

## 5. Check the new backup opens with the new key, and not with the old one

1. Download that file from the Backblaze bucket page into an empty folder, e.g.
   `~/veilcore-check` (`mkdir -m 700 ~/veilcore-check`). Call it `FILE.sqlite.gz.age` below.
2. Copy the **new** private key from the password manager, then, in that folder:

   ```
   cd ~/veilcore-check
   age -d -i <(pbpaste | grep -o 'AGE-SECRET-KEY-[0-9A-Z]*') FILE.sqlite.gz.age | gunzip > restored.db
   pbcopy < /dev/null      # clear the clipboard
   sqlite3 restored.db "PRAGMA integrity_check; SELECT count(*) FROM records;"
   ```

   The key goes from the clipboard straight to `age` through a pipe: it is never written to
   a file or shown. `ok` and the record count mean the backup is good.
3. Check it is the purged database: from the registry folder,

   ```
   node scripts/purge-plaintext.mjs --db ~/veilcore-check/restored.db
   ```

   prints a dry run (it changes nothing). Its counts should match what the purge left on the
   live database: 0 sealed records whose clear fields are to be cut, 0 transfers to empty,
   0 handles to replace. Rows it still lists as "reported" or "skipped" are the holders the
   purge deliberately left alone; they are in the live database too.
4. Copy the **old** private key and try it on the same file:

   ```
   age -d -i <(pbpaste | grep -o 'AGE-SECRET-KEY-[0-9A-Z]*') FILE.sqlite.gz.age > /dev/null
   pbcopy < /dev/null
   ```

   It must fail with `no identity matched any of the recipients`. If it opens, the
   registry is still using the old key: go back to step 3.
5. Delete the check folder: `rm -r ~/veilcore-check`.

## 6. Destroy the old private key

Only after step 5 passed.

1. In the password manager, delete the **old** "VeilCore backup key" item. Then empty the
   password manager's trash ("Recently Deleted" in 1Password, "Trash" in Bitwarden), and
   delete any older versions of the item if the manager keeps item history.
2. Look for copies on this computer and delete them:

   ```
   find ~ -name 'veilcore-backup-key*' -o -name 'restored.db' 2>/dev/null
   ```

   Delete what it lists (`rm <path>`), and empty the Bin.
3. Any other copy (printed, on a USB stick, in another password manager, sent to someone):
   destroy it. Ask anyone who was given it to delete theirs.
4. Railway: if the service's volume has Railway backups (service, Volume, Backups), delete
   the ones taken before the purge. They are full copies of the database, not encrypted to
   our key.

From now on, only backups whose name says `key-<new id>` can be opened. Older ones (named
`key-<old id>`, or with no `key-` part at all) stay in the bucket until their 30-day lock
and the lifecycle rule remove them, but nobody can read them.

## 7. Afterwards

1. Write down the date and the new key id where the team keeps operational notes.
2. Only now may the site or anything else say that VeilCore can't read backups made before
   sealing.
3. Run the restore check (README, "Restoring, or checking a backup can be restored") with
   the new key now and then, as before.
