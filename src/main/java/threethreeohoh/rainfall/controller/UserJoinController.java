package threethreeohoh.rainfall.controller;


import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import threethreeohoh.rainfall.dto.UserJoinDTO;
import threethreeohoh.rainfall.service.UserJoinService;

@RestController
@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600)
public class UserJoinController {

    private final UserJoinService userJoinService;

    public UserJoinController(UserJoinService userJoinService) {
        this.userJoinService = userJoinService;
    }

    @PostMapping("/join")
    public String userJoinProcess(UserJoinDTO userJoinDTO) {
        userJoinService.userJoinProcess(userJoinDTO);
        return "ok";
    }
}
