package me.mrexplode.warehouse;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

import javax.swing.JTextArea;

public class StreamCapturer extends OutputStream {
    
    private StringBuilder buffer;
    private JTextArea consumer;
    private PrintStream old;
    
    public StreamCapturer(JTextArea consumer, PrintStream old) {
        buffer = new StringBuilder(128);
        this.old = old;
        this.consumer = consumer;
    }

    @Override
    public void write(int b) throws IOException {
        char c = (char) b;
        String value = Character.toString(c);
        buffer.append(value);
        if (value.equals("\n")) {
            consumer.append(buffer.toString());
            buffer.delete(0, buffer.length());
        }
        old.print(c);
    }

}
