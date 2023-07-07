package com.security.jwtsecurity.config;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private static final String SECRET_KEY = "9S84ApnFOa3z5CyhHG6jZirzxj+2l6HR8bzr5AOMMcARwXV9NafjKnnWMPSCXpOoNICbYf39MXg/5LRUavxrXhne16rTy83fo7Zxex9rOYcnYSclb1g1DjOfRHyiAast15GIdtRdPq+6JHbODXyqpnf6xpBjcGcY7D1yCtXEaYJKebU5FLZmnAv5r+so7FO08JOGAlhets3G1Ia/hFRljyNzxx8AcOX1QtjrdD2W/TzvVlfH7r75mtFU8hb2diQl1dul3PbRaSiUwEqXXLG0Gud2erZC1lLZs2jEN/M7NEYHdqxYclzuuHQNGvOliQKeR2eTbruP608nDH5MulgFxNiYPMFoo2Hw89yM8o57uzo=\r\n";
    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }

    public String generateJwtToken(UserDetails userDetails) {
        return generateJwtToken(new HashMap<>(), userDetails);
    }

    public String generateJwtToken(Map<String, Object> extraClaims, UserDetails userdetails) {
        return Jwts
        .builder()
        .setClaims(extraClaims)
        .setSubject(userdetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis()+1000*24*60))
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)
        .compact();
    }

    public boolean isJwtTokenValid(String jwtToken, UserDetails userDetails) {
        return extractUsername(jwtToken).equals(userDetails.getUsername()) && !isJwtTokenExpired(jwtToken);
    }

    private boolean isJwtTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }

    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }

    public <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jwtToken);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String jwtToken) {
        return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(jwtToken).getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
