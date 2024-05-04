package com.ilyainavoid.otpauthlab.models.dtos;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class SecretAddResponse {
    private boolean done;
    private Metadata metadata;
    private String id;
    private String description;
    private String createdAt;
    private String createdBy;
    private String modifiedAt;

    @Data
    public static class Metadata {
        @SerializedName("@type")
        private String type;
        private String secretId;
        private String versionId;

    }

    public static SecretAddResponse fromJson(String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, SecretAddResponse.class);
    }
}
