package com.vpbank.dcp.core.port.out.guard;

public interface SubjectBlockStore {

    SubjectBlockResult apply(SubjectBlock block);
}
