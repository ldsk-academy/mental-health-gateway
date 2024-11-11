package br.com.mh.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class JwtUtil {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String PREFIX_ROLE = "ROLE_";

    private static final String SECRET = "2OC9-B5cWopAxe88xZd1Q8RcznXHniIK4k6Tr2L1zO8=";
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));


    public String getJwtFromRequest(HttpServletRequest httpServletRequest) {

        String token = httpServletRequest.getHeader("Authorization");

        if(StringUtils.hasText(token) && token.startsWith(BEARER_PREFIX)) {

            return token.replace(BEARER_PREFIX, "");
        }

        return null;
    }

    public String getSubjectFromJwt(String token) {

        return extractAllClaims(token).getSubject();
    }

    public List<String> getRolesFromJwt(String token) {

        return extractAllClaims(token).get("roles", List.class);
    }

    private String formatRoleName(String role) {

        return PREFIX_ROLE.concat(role);
    }

    private Claims extractAllClaims(String token) {

        return Jwts.parser().verifyWith(SECRET_KEY).build().parseSignedClaims(token).getPayload();
    }

}
