package br.com.mh.security.filter;

import br.com.mh.dto.TokenDto;
import br.com.mh.security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final RestTemplate restTemplate;
    private final JwtUtil jwtUtil;

    @Value("${mental.health.validate-token.url}")
    private String validateTokenUrl;

    @Autowired
    public JwtAuthenticationFilter(JwtUtil jwtUtil) {

        this.restTemplate = new RestTemplate();
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = jwtUtil.getJwtFromRequest(request);

        if(token != null && validateToken(token)) {

            String username = jwtUtil.getSubjectFromJwt(token);
            List<String> roles = jwtUtil.getRolesFromJwt(token);

            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(username, null, toSimpleGrantedAuthority(roles))
            );
        }

        filterChain.doFilter(request, response);
    }

    private boolean validateToken(String token) {

        try {

            return restTemplate.exchange(
                    validateTokenUrl,
                    HttpMethod.POST,
                    new HttpEntity<>(new TokenDto(token)),
                    Void.class
            ).getStatusCode().is2xxSuccessful();
        } catch (Exception e) {

            return false;
        }
    }

    private List<SimpleGrantedAuthority> toSimpleGrantedAuthority(List<String> roles) {

        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        String path = request.getServletPath();

        return path.equals("/mental-health-user-auth/auth/register")
                || path.equals("/mental-health-user-auth/auth/login");
    }

}
