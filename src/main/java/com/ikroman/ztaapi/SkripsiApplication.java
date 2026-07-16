package com.ikroman.ztaapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class SkripsiApplication {

	public static void main(String[] args) {
		SpringApplication.run(SkripsiApplication.class, args);
	}

}
