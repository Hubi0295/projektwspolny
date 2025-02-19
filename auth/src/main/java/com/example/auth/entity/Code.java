package com.example.auth.entity;

public enum Code {
    SUCCESS("Operacja zakończona sukcesem"),
    PERMIT("Przyznano dostep"),
    A1("Podany uzytkownik o danej nazwie nie istnieje lub nie aktywował konta"),
    A2("Podane dane są nieprawidłowe"),
    A3("Wskazany token jest pusty lub nie ważny"),
    A4("Użytkownik o podanej nazwie juz istnieje"),
    A5("Użytkownik o podanmym mailu juz istnieje"),
    A6("Użytkownik nie istnieje");


    public final String label;
    private Code(String label){
        this.label=label;
    }
}
