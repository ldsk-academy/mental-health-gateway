package br.com.mh.dto;

import lombok.Getter;

@Getter
public class TokenDto {

    public TokenDto(String token) {

        this.token = token;
    }

    private String token;

}
