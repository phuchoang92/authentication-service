package com.vpbank.archfixtures.infrastructure.persistence.adapter;

import jakarta.persistence.EntityManager;
import com.vpbank.archfixtures.infrastructure.persistence.entity.BadEntity;

public class BadSqlAdapter {
    EntityManager sql;
    BadEntity leakedEntity;
}
