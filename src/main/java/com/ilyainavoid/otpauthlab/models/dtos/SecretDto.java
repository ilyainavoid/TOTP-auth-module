package com.ilyainavoid.otpauthlab.models.dtos;

import lombok.Data;

@Data
public class SecretDto {
    private String key;
    private String textValue;
}
