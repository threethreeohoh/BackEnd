package threethreeohoh.rainfall.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.filter.OncePerRequestFilter;
import threethreeohoh.rainfall.dto.CustomUserDetails;
import threethreeohoh.rainfall.entity.UserEntity;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter { // 요청에 대해 한번만 동작하는 OncePerRequestFilter을 상속받음

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request 에서 Authorization 헤더를 찾음
        String authorization = request.getHeader("Authorization");

        // Authorization 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) { // 정상적으로 헤더가 존재하지 않는다면 다음 필터로 요청(request)과 응답(response)을 넘겨주고 현재 메서드 종료

            System.out.println("token is null");
            filterChain.doFilter(request, response); // 다음 필터로 요청과 응답을 넘겨줌

            // 조건이 해당되면 메서드 종료 (필수)
            return;
        }

        String token = authorization.split(" ")[1]; // "Bearer " 부분을 제거한 순수 토큰만 가져옴

        // 토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) { // 토큰 만료 시  다음 필터로 요청(request)과 응답(response)을 넘겨주고 메서드 종료
            System.out.println("token is expired");
            filterChain.doFilter(request, response);

            return;
        }

        // 여기까지 총 2개의 if 조건문을 거쳐 토큰 검증에 통과한 경우만 남음
        // 이제 토큰에서 username과 role 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // 비밀번호(password)의 경우 토큰에 담겨있지 X. 비밀번호도 같이 초기화 해줘야 함
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername(username);
        userEntity.setPassword("temporaryPassword"); // 매번 요청 시 DB를 조회해야되는 비효율적인 상황 방지를 위해 임시적인 비밀번호를 강제로 만듦
        userEntity.setRole(role);

        // UserDetails에 회원 정보 객체 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        // 세션에 사용자 등록 (유저 세션 생성하여 이제 특정 경로에 접근 가능)
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response); // 다음 필터에 요청(request)과 응답(response)을 넘겨줌
    }
}
