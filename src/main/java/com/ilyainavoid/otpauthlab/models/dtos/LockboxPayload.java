package com.ilyainavoid.otpauthlab.models.dtos;

import lombok.Data;

import java.util.List;

@Data
public class LockboxPayload {
    private List<SecretDto> entries;
    private String versionId;
}
