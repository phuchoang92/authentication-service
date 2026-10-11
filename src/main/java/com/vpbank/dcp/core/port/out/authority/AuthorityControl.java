package com.vpbank.dcp.core.port.out.authority;

public interface AuthorityControl {

    ControlCloseResult close(ControlClosure closure);
}
