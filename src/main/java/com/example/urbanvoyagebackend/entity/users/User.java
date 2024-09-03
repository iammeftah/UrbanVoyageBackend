package com.example.urbanvoyagebackend.entity.users;

import com.example.urbanvoyagebackend.entity.travel.Passenger;
import com.example.urbanvoyagebackend.entity.travel.Reservation;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Inheritance(strategy = InheritanceType.JOINED)
public abstract class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long userID;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Column(nullable = false, unique = true)
    private String phoneNumber;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @ElementCollection(targetClass = Role.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>();


    @JsonIgnore
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<Reservation> reservations = new HashSet<>();

    @JsonIgnore
    @OneToMany(mappedBy = "createdByUser", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Set<Passenger> createdPassengers = new HashSet<>();

    private String verificationCode;
    private boolean verified;

    // Constructors
    public User() {}

    public User(String firstName, String lastName, String phoneNumber, String email, String username, String password) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.phoneNumber = phoneNumber;
        this.email = email;
        this.username = username;
        this.password = password;
    }

    public User(Long userID, String firstName, String lastName, String phoneNumber, String email, String username, String password, Set<Role> roles, Set<Reservation> reservations, String verificationCode, boolean verified) {
        this.userID = userID;
        this.firstName = firstName;
        this.lastName = lastName;
        this.phoneNumber = phoneNumber;
        this.email = email;
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.reservations = reservations;
        this.verificationCode = verificationCode;
        this.verified = verified;
    }

    // Getters and setters (unchanged)


    public Long getUserID() {
        return userID;
    }

    public void setUserID(Long userID) {
        this.userID = userID;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Set<Reservation> getReservations() {
        return reservations;
    }

    public void setReservations(Set<Reservation> reservations) {
        this.reservations = reservations;
    }

    public String getVerificationCode() {
        return verificationCode;
    }

    public void setVerificationCode(String verificationCode) {
        this.verificationCode = verificationCode;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    // Helper method to add a role
    public void addRole(Role role) {
        this.roles.add(role);
    }

    // Helper method to remove a role
    public void removeRole(Role role) {
        this.roles.remove(role);
    }

    // Helper method to add a reservation
    public void addReservation(Reservation reservation) {
        this.reservations.add(reservation);
        reservation.setUser(this);
    }

    // Helper method to remove a reservation
    public void removeReservation(Reservation reservation) {
        this.reservations.remove(reservation);
        reservation.setUser(null);
    }

    public Set<Passenger> getCreatedPassengers() {
        return createdPassengers;
    }

    public void setCreatedPassengers(Set<Passenger> createdPassengers) {
        this.createdPassengers = createdPassengers;
    }

    // Helper method to add a created passenger
    public void addCreatedPassenger(Passenger passenger) {
        this.createdPassengers.add(passenger);
        passenger.setCreatedByUser(this);
    }

    // Helper method to remove a created passenger
    public void removeCreatedPassenger(Passenger passenger) {
        this.createdPassengers.remove(passenger);
        passenger.setCreatedByUser(null);
    }

}