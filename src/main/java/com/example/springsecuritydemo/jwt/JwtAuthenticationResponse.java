package com.example.springsecuritydemo.jwt;

import com.example.springsecuritydemo.dao.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

//will remove this
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class JwtAuthenticationResponse {

    private String accessToken;

    private String refreshToken;

}
