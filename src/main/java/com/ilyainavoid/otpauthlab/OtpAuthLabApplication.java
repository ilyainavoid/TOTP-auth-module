package com.ilyainavoid.otpauthlab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication
public class OtpAuthLabApplication {

    public static void main(String[] args) {
        SpringApplication.run(OtpAuthLabApplication.class, args);
    }

}
