package com.example.productservice.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;
import java.util.Map;
import java.util.Set;
@MappedSuperclass
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Product {
    @Id
    @GeneratedValue(generator = "products_id_seq", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name="products_id_seq", sequenceName = "products_id_seq", allocationSize = 1)
    private long id;
    private String uid;
    private boolean activated;
    @Column(name="product_name")
    private String name;
    private String mainDesc;
    private String descHtml;
    private float price;
    private String[] imageUrls;
    private String parameters;
    private LocalDate createdAt;


}

