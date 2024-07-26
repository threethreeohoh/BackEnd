package threethreeohoh.rainfall.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsMvcConfig implements WebMvcConfigurer { // 일반 Controller의 CORS 설정

    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) { // 모든 Controller 경로에 대해 http://localhost:3000 에서 오는 요청을 허용
        corsRegistry.addMapping("/**")
                //.allowedOrigins("http://localhost:3000")
                .allowedOrigins("*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
