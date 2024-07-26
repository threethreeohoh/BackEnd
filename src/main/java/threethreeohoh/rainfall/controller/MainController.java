package threethreeohoh.rainfall.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Iterator;


@RestController
@CrossOrigin
public class MainController {

    @GetMapping("/")
    public String mainP() {

        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        // role 값의 경우 collection의 iterator를 통해 반복자로 데이터를 꺼내야 함
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        return "Main Controller : " + username + role;
    }
}
