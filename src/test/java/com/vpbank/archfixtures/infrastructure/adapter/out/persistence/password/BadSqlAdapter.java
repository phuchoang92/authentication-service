package com.vpbank.archfixtures.infrastructure.adapter.out.persistence.password;

import jakarta.persistence.EntityManager;
import com.vpbank.archfixtures.infrastructure.adapter.out.persistence.repository.password.BadEntity;

public class BadSqlAdapter {
    EntityManager sql;
    BadEntity leakedEntity;
}
