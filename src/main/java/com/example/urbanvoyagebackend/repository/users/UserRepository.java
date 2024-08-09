// UserRepository.java
package com.example.urbanvoyagebackend.repository.users;

import com.example.urbanvoyagebackend.entity.users.Role;
import com.example.urbanvoyagebackend.entity.users.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
    boolean existsByPhoneNumber(String phoneNumber);
    Optional<User> findByEmail(String email);

    @Query("SELECT u.email FROM User u JOIN u.roles r WHERE r = :role")
    List<String> findEmailsByRole(@Param("role") Role role);
}

