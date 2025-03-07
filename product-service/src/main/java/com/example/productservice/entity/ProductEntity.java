package com.example.productservice.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

import java.time.LocalDate;

@Table(name="products")
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ProductEntity extends Product{
    @ManyToOne
    @JoinColumn(name = "category_parameters")
    private Category category;

    public ProductEntity(long id, String uid, boolean activated, String name, String mainDesc, String descHtml, float price, String[] imageUrls, String parameters, LocalDate createdAt, Category category) {
        super(id, uid, activated, name, mainDesc, descHtml, price, imageUrls, parameters, createdAt);
        this.category = category;
    }

}
