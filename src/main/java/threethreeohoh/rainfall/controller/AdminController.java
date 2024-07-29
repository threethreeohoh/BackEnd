package threethreeohoh.rainfall.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600)
public class AdminController {

    @GetMapping("/admin")
    public String mainP() {
        return "Admin Controller";
    }
}
