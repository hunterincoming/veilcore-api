import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type Witnesses<PS> = {
  localGeneticSecret(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, Uint8Array];
}

export type ImpureCircuits<PS> = {
  proposeParent(context: __compactRuntime.CircuitContext<PS>,
                parentCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  confirmParent(context: __compactRuntime.CircuitContext<PS>,
                childCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  withdrawParent(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
  proposeObligation(context: __compactRuntime.CircuitContext<PS>,
                    recordCommitment_0: Uint8Array,
                    obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  encumberOwnRecord(context: __compactRuntime.CircuitContext<PS>,
                    obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  withdrawObligation(context: __compactRuntime.CircuitContext<PS>,
                     recordCommitment_0: Uint8Array,
                     obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  acceptObligation(context: __compactRuntime.CircuitContext<PS>,
                   obligationCommitment_0: Uint8Array,
                   beneficiaryCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  discharge(context: __compactRuntime.CircuitContext<PS>,
            recordCommitment_0: Uint8Array,
            obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  proveAncestorClean(context: __compactRuntime.CircuitContext<PS>,
                     ancestorCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type ProvableCircuits<PS> = {
  proposeParent(context: __compactRuntime.CircuitContext<PS>,
                parentCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  confirmParent(context: __compactRuntime.CircuitContext<PS>,
                childCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  withdrawParent(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
  proposeObligation(context: __compactRuntime.CircuitContext<PS>,
                    recordCommitment_0: Uint8Array,
                    obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  encumberOwnRecord(context: __compactRuntime.CircuitContext<PS>,
                    obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  withdrawObligation(context: __compactRuntime.CircuitContext<PS>,
                     recordCommitment_0: Uint8Array,
                     obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  acceptObligation(context: __compactRuntime.CircuitContext<PS>,
                   obligationCommitment_0: Uint8Array,
                   beneficiaryCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  discharge(context: __compactRuntime.CircuitContext<PS>,
            recordCommitment_0: Uint8Array,
            obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  proveAncestorClean(context: __compactRuntime.CircuitContext<PS>,
                     ancestorCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type PureCircuits = {
  commit(secret_0: Uint8Array): Uint8Array;
  descentEdge(child_0: Uint8Array, parent_0: Uint8Array): Uint8Array;
  obligationKey(recordCommitment_0: Uint8Array,
                obligationCommitment_0: Uint8Array,
                beneficiaryCommitment_0: Uint8Array): Uint8Array;
}

export type Circuits<PS> = {
  commit(context: __compactRuntime.CircuitContext<PS>, secret_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  descentEdge(context: __compactRuntime.CircuitContext<PS>,
              child_0: Uint8Array,
              parent_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  obligationKey(context: __compactRuntime.CircuitContext<PS>,
                recordCommitment_0: Uint8Array,
                obligationCommitment_0: Uint8Array,
                beneficiaryCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, Uint8Array>;
  proposeParent(context: __compactRuntime.CircuitContext<PS>,
                parentCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  confirmParent(context: __compactRuntime.CircuitContext<PS>,
                childCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  withdrawParent(context: __compactRuntime.CircuitContext<PS>): __compactRuntime.CircuitResults<PS, []>;
  proposeObligation(context: __compactRuntime.CircuitContext<PS>,
                    recordCommitment_0: Uint8Array,
                    obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  encumberOwnRecord(context: __compactRuntime.CircuitContext<PS>,
                    obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  withdrawObligation(context: __compactRuntime.CircuitContext<PS>,
                     recordCommitment_0: Uint8Array,
                     obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  acceptObligation(context: __compactRuntime.CircuitContext<PS>,
                   obligationCommitment_0: Uint8Array,
                   beneficiaryCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  discharge(context: __compactRuntime.CircuitContext<PS>,
            recordCommitment_0: Uint8Array,
            obligationCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
  proveAncestorClean(context: __compactRuntime.CircuitContext<PS>,
                     ancestorCommitment_0: Uint8Array): __compactRuntime.CircuitResults<PS, []>;
}

export type Ledger = {
  readonly descentSeq: bigint;
  readonly descentProposalSeq: bigint;
  readonly obligationSeq: bigint;
  readonly cleanProofSeq: bigint;
  readonly lastDescent: Uint8Array;
  readonly lastDescentChild: Uint8Array;
  readonly lastDescentParent: Uint8Array;
  readonly lastObligationRecord: Uint8Array;
  readonly lastObligation: Uint8Array;
  readonly lastBeneficiary: Uint8Array;
  readonly lastCleanProofBy: Uint8Array;
  readonly lastClearedAncestor: Uint8Array;
  pendingParentOf: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): Uint8Array;
    [Symbol.iterator](): Iterator<[Uint8Array, Uint8Array]>
  };
  pendingObligations: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: Uint8Array): boolean;
    [Symbol.iterator](): Iterator<Uint8Array>
  };
  openObligations: {
    isEmpty(): boolean;
    size(): bigint;
    member(elem_0: Uint8Array): boolean;
    [Symbol.iterator](): Iterator<Uint8Array>
  };
  obligationCountOf: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: Uint8Array): boolean;
    lookup(key_0: Uint8Array): bigint;
    [Symbol.iterator](): Iterator<[Uint8Array, bigint]>
  };
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
