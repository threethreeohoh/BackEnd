package threethreeohoh.rainfall.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import threethreeohoh.rainfall.jwt.JWTFilter;
import threethreeohoh.rainfall.jwt.JWTUtil;
import threethreeohoh.rainfall.jwt.LoginFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // 특정 HTTP 요청에 대한 웹 기반 보안 구성 (인증/인가 및 로그아웃을 설정)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity // CSRF 보호 기능을 비활성화
                .csrf(AbstractHttpConfigurer::disable);
        httpSecurity // HTTP Basic 인증을 비활성화
                .httpBasic(AbstractHttpConfigurer::disable);
        httpSecurity // 폼 로그인 기능을 비활성화
                .formLogin(AbstractHttpConfigurer::disable);
        httpSecurity // 인가 작업
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .anyRequest().authenticated());
        httpSecurity // 로그아웃 설정
                .logout((logout) -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
        httpSecurity // 세션 관리 정책 설정 (Stateless)
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        httpSecurity // jwt 토큰을 검증하는 필터 등록
                .addFilterBefore(new JWTFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        httpSecurity // 로그인을 검증하는 필터 등록
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class); // UsernamePasswordAuthenticationFilter 를 딱 대체하는 필터를 만든 것이기 때문에 Before나 After이 아닌 At으로 설정

        return httpSecurity.build();
    }

    @Bean
    public static BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
