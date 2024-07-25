package threethreeohoh.rainfall.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import threethreeohoh.rainfall.dto.CustomUserDetails;
import threethreeohoh.rainfall.entity.UserEntity;
import threethreeohoh.rainfall.repository.UserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // DB에서 특정 유저를 조회해 리턴해주면 됨

        UserEntity userEntity = userRepository.findByUsername(username);

        if(userEntity != null) {
            return new CustomUserDetails(userEntity);
        }
        throw new UsernameNotFoundException("Username not found");
    }
}
