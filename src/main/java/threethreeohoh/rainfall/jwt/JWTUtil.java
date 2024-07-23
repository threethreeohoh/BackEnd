package threethreeohoh.rainfall.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil { // JWT의 발급과 검증 메서드를 구현할 클래스

    private SecretKey secretKey;

    public  JWTUtil(@Value("${spring.jwt.secret}")String secret) { // 객체 변수로 받은 파라미터 키(application.yaml파일에 있는 키)를 기반으로 새로운 객체 키(secretKey)를 생성함
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }

    public  String getUsername(String token) { // 토큰을 전달 받아 username 검증 메서드
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
    }

    public String getRole(String token) { // role 검증 메서드
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) { // 토근 만료 검증 메서드
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    public String createJwt(String username, String role, Long expiredMs) { // 로그인 완료 시 successful handler를 통해서 파라미터 값들을 전달 받아 토큰 생성 후 응답해주는 메서드
        return Jwts.builder()
                .claim("username", username)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis())) // 토큰 현재 발행시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 토근 만료 시간
                .signWith(secretKey) // 암호화
                .compact();
    }
}
