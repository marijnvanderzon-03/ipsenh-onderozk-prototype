package com.ipsenh.prototype.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ipsenh.prototype.model.*;

@Repository
public interface AccountRepository extends JpaRepository<Account, String> {
    Account findByUsername(String username);
}

