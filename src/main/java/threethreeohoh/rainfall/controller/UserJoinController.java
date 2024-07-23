package threethreeohoh.rainfall.controller;


import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import threethreeohoh.rainfall.dto.UserJoinDTO;
import threethreeohoh.rainfall.service.UserJoinService;

@Controller
@ResponseBody
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
