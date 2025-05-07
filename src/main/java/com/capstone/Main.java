package com.capstone;

import com.capstone.hors.HORS;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner sc = new Scanner(System.in);
        int N = 128, T = 65536, K = 256;
        HORS h = new HORS(N, T, K);

        h.generateKeys();

        int size = 1000;

        // Warming up the JIT
        for (int i = 0; i < 1000; i++) {
            h.signMessage("Message".getBytes(), h.getSecretKey());
        }

        while (!Objects.equals(sc.next(), "-1")) {
            long sumSign = 0L;

            String[] arr = new String[size];

            for (int i = 0; i < arr.length; i++) {
                arr[i]="New Message itur7jehy6gt5w4grbyn4wth5gwtnthy564rev"+i+";"+(Math.pow(i,i));
            }

            List<byte[][]> sigs = new ArrayList<>();

            for (int i = 0; i < size; i++) {
                String msg = arr[i];

                long now = System.nanoTime();
                byte[][] sig = h.signMessage(msg.getBytes(), h.getSecretKey());
                long signed = System.nanoTime();
                sumSign += signed - now;
                sigs.add(sig);
            }


            long averageSign = sumSign /size;
            System.out.printf("Average signing time: %d nanoseconds\n", averageSign);

            long sumVerify = 0L;

            for (int i = 0; i < size; i++) {

                String msg = arr[i];

                long now = System.nanoTime();
                boolean verify = h.verifySignature(msg.getBytes(),sigs.get(i), h.getPublicKey());
                long verified = System.nanoTime();
                sumVerify+= verified - now;

                if(!verify) System.out.println("Incorrect signature");

            }
            long averageVerify = sumVerify/size;
            System.out.printf("Average verifying time: %d nanoseconds\n\n",averageVerify);

            System.out.printf("""
                    Total signing time of %d messages: %d nanoseconds
                    Total verifying time of %d signatures:\
                     %d nanoseconds
                    
                    """,size, sumSign,size,sumVerify);
        }
    }
}