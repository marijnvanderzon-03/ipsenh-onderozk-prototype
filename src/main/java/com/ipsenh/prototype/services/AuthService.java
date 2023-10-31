package com.ipsenh.prototype.services;

import com.ipsenh.prototype.Payloads.SignupRequest;
import com.ipsenh.prototype.model.Account;
import com.ipsenh.prototype.repositories.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    @Autowired
    AccountRepository accountRepository;
    @Autowired
    EncryptionService encryptionService;

    public Boolean usernameTaken(String username){
        Account account = accountRepository.findByUsername(username);
        return account !=null;
    }

    public void createAndSaveUser(SignupRequest signupRequest){
        Account account = new Account();
        account.setUsername(signupRequest.getUsername());
        account.setPassword(encryptionService.hashPassword(signupRequest.getPassword()));
        System.out.println(account.getPassword());
        accountRepository.save(account);
    }

}
