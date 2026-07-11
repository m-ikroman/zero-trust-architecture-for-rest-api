package com.ikroman.ztaapi.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/** Request body untuk membuat/memperbarui resource */
@Data
public class ResourceRequest {

    @NotBlank(message = "Judul tidak boleh kosong")
    @Size(max = 200)
    private String title;

    @Size(max = 1000)
    private String content;

    // sensitiveData hanya bisa diset melalui endpoint admin (menguji API3 BOPLA)
    @Size(max = 500)
    private String sensitiveData;
}
