package com.turingdi.trafficforecast.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * @Description:
 * @Date: Created in 2018-04-03
 * @Author: created by victorys_tan
 */
@RestController
@RequestMapping("thymeleaf")
public class ThymeleafController {

    @GetMapping("/admin")
    public ModelAndView admin() {
        return new ModelAndView("admin");
    }

    @GetMapping("/user")
    public ModelAndView user() {
        return new ModelAndView("user");
    }

    @GetMapping("/home")
    public ModelAndView home() {
        return new ModelAndView("home");
    }

}
