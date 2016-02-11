package co.masslab;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/echo")
public class EchoController {

    @RequestMapping(value="/{word}")
    public String echo(@PathVariable("word") String word) {
        return word;
    }
}
