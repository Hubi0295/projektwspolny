package com.example.gatway.utils;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
@Component
public class JwtUtil {
    public JwtUtil(@Value("${jwt.secret}") String secret){
        SECRET = secret;
    }

    public final String SECRET ;
    public void validateToken(final String token){
        Jwts.parserBuilder().setSigningKey(getSingKey()).build().parseClaimsJws(token);
    }
    private Key getSingKey(){
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
