package threethreeohoh.rainfall.service;

import org.springframework.security.core.parameters.P;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import threethreeohoh.rainfall.dto.UserJoinDTO;
import threethreeohoh.rainfall.entity.UserEntity;
import threethreeohoh.rainfall.repository.UserRepository;

@Service
public class UserJoinService {

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder; // 사용자가 입력한 비밀번호 암호화하면서 레포지토리에 저장하기 위해 사용

    public UserJoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public Boolean userJoinProcess(UserJoinDTO userJoinDTO) {

        String username = userJoinDTO.getUsername();
        String password = userJoinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist) { // 이미 username(email)이 존재한다면 false 리턴
            return false;
        }

        UserEntity userEntity = new UserEntity(); // userJoinDTO에서 받은 데이터를 UserEntity에 그대로 옮겨줌
        userEntity.setUsername(username);
        userEntity.setPassword(bCryptPasswordEncoder.encode(password)); // password의 경우 무조건 암호화를 진행한 후 넣어야 하기 때문에 config/SecurityConfig에서 @Bean으로 등록해둔 BCryptPasswordEncoder을 여기서 주입받아 사용할 것임
        userEntity.setRole("ROLE_ADMIN"); // 회원가입하는 모든 사람을 우선 ADMIN 권한을 줄거임

        userRepository.save(userEntity); // 받은 사용자 정보 레포지토리에 저장

        return true;
    }
}
