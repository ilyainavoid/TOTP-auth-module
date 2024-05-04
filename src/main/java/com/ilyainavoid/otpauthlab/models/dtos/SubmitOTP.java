package com.ilyainavoid.otpauthlab.models.dtos;

import lombok.Data;

@Data
public class SubmitOTP {
    private String Code;
    private String username;
}
