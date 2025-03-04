package com.example.productservice.mediator;

import com.example.productservice.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ProductMediator {
    private final ProductService productService;
    public ResponseEntity<?> getProduct(int page, int limit){
        long totalCount = productService.countActiveProducts();
        return ResponseEntity.ok().header("X-Total-Count",String.valueOf(totalCount)).body("");
    }
}
