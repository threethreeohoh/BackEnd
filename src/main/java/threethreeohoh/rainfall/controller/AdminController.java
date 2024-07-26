package threethreeohoh.rainfall.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@CrossOrigin
public class AdminController {

    @GetMapping("/admin")
    public String mainP() {
        return "Admin Controller";
    }
}
