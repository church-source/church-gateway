package org.churchsource.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtTokenService implements Serializable {

  static final String CLAIM_KEY_USERNAME = "sub";
  static final String CLAIM_KEY_CREATED = "iat";
  private static final long serialVersionUID = -3301605591108950415L;
  public static final String JWT_TOKEN_REASON = "reason";
  public static final String JWT_TOKEN_REASON_PASSWORD_CHANGE = "passwordChange";
  private Clock clock = DefaultClock.INSTANCE;

  @Value("${jwt.signing.key.secret}")
  private String secret;

  public String getUsernameFromToken(String token) {
    return getClaimFromToken(token, Claims::getSubject);
  }

  public Date getExpirationDateFromToken(String token) {
    return getClaimFromToken(token, Claims::getExpiration);
  }

  public String getReasonFromToken(String token) {
    return (String)Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody().get(JWT_TOKEN_REASON);
  }

  public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = getAllClaimsFromToken(token);
    return claimsResolver.apply(claims);
  }

  private Claims getAllClaimsFromToken(String token) {
    return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
  }

  public Boolean isTokenExpired(String token) {
    try {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(clock.now());
    } catch(ExpiredJwtException e) {
        return true;
    }
  }

  public Boolean validateToken(String token) {
    try {
        return (!isTokenExpired(token));
    } catch (ExpiredJwtException e) {
        return false;
    }
  }
}

