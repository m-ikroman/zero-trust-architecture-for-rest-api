package com.ikroman.ztaapi.repository;

import com.ikroman.ztaapi.entity.Resource;
import com.ikroman.ztaapi.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ResourceRepository extends JpaRepository<Resource, Long> {
    List<Resource> findByOwner(User owner);
    Optional<Resource> findByIdAndOwner(Long id, User owner);
}
