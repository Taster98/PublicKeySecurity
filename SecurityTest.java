import Exceptions.NoPointException;
import Exceptions.PointToInfiniteException;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class SecurityTest {
    //Messaggi cifrati per 10,16,20,24,25 bit:
    private static int m10 = 7;
    private static int m16 = 13;
    private static int m20 = 17;
    private static int m24 = 29;
    private static int m25 = 251;
    //RSA:
    //p=37, q=19 10-bit
    private static RSA cfrRSA10 = new RSA(BigInteger.valueOf(37),BigInteger.valueOf(19));
    //p=241 q=157 16-bit
    private static RSA cfrRSA16 = new RSA(BigInteger.valueOf(241),BigInteger.valueOf(157));
    //p=397 q=1597 20-bit
    private static RSA cfrRSA20 = new RSA(BigInteger.valueOf(397),BigInteger.valueOf(1597));
    //p=3947 q=2557 24-bit
    private static RSA cfrRSA24 = new RSA(BigInteger.valueOf(3947),BigInteger.valueOf(2557));
    //p=3001 q=5743 25-bit
    private static RSA cfrRSA25 = new RSA(BigInteger.valueOf(3001),BigInteger.valueOf(5743));


    //ECC:
    //10 bit E_823(-1,1)
    private static ECC cfrECC10 = new ECC(BigInteger.valueOf(-1),BigInteger.valueOf(1),BigInteger.valueOf(823));
    private static ECPoint B10 = new ECPoint(cfrECC10.getA(),cfrECC10.getB(),cfrECC10.getP(),BigInteger.valueOf(19),BigInteger.valueOf(293));
    private static ECPoint Pd10;
    private static BigInteger prvKey10 = BigInteger.valueOf(899);
    //16 bit E_46133(-1,1)
    private static ECC cfrECC16 = new ECC(BigInteger.valueOf(-1),BigInteger.valueOf(1),BigInteger.valueOf(46133));
    private static ECPoint B16 = new ECPoint(cfrECC16.getA(),cfrECC16.getB(),cfrECC16.getP(),BigInteger.valueOf(113),BigInteger.valueOf(35151));
    private static ECPoint Pd16;
    private static BigInteger prvKey16 = BigInteger.valueOf(41899);
    //20 bit E_761291(-1,1)
    private static ECC cfrECC20 = new ECC(BigInteger.valueOf(-1),BigInteger.valueOf(1),BigInteger.valueOf(761291));
    private static ECPoint B20 = new ECPoint(cfrECC20.getA(),cfrECC20.getB(),cfrECC20.getP(),BigInteger.valueOf(167),BigInteger.valueOf(539846));
    private static ECPoint Pd20;
    private static BigInteger prvKey20 = BigInteger.valueOf(641899);
    //24 bit E_8812313(-1,1)
    private static ECC cfrECC24 = new ECC(BigInteger.valueOf(-1),BigInteger.valueOf(1),BigInteger.valueOf(8812313));
    private static ECPoint B24 = new ECPoint(cfrECC24.getA(),cfrECC10.getB(),cfrECC10.getP(),BigInteger.valueOf(773),BigInteger.valueOf(3443266));
    private static ECPoint Pd24;
    private static BigInteger prvKey24 = BigInteger.valueOf(9341899);
    //25 bit E_28123133(-1,1)
    private static ECC cfrECC25 = new ECC(BigInteger.valueOf(-1),BigInteger.valueOf(1),BigInteger.valueOf(28123133));
    private static ECPoint B25 = new ECPoint(cfrECC25.getA(),cfrECC25.getB(),cfrECC25.getP(),BigInteger.valueOf(2903),BigInteger.valueOf(14901307));
    private static ECPoint Pd25;
    private static BigInteger prvKey25 = BigInteger.valueOf(17341899);

    //funzioni cifrari
    public static BigInteger RSA_Encrypt(RSA cfr, int m){
        System.out.println("Il mittente Alice cifra il messaggio m = "+m+" con i dati e = "+cfr.getE()+", n = "+cfr.getN()+"\n\n");
        BigInteger msg = BigInteger.valueOf(m);
        System.out.println("La lunghezza della chiave è "+cfr.getD().bitLength()+" bit.\n");
        BigInteger crt = cfr.Encrypt(msg,cfr.getN(),cfr.getE());
        System.out.println("Alice genera quindi il crittogramma crt = "+crt+" e lo spedisce a Bob\n");
        return crt;
    }

    public static Pair<ECPoint,ECPoint> ECC_Encrypt(ECC cfr, int m, ECPoint B, BigInteger prvKey){
        System.out.println("Il mittente Alice cifra il messaggio m = "+m+" con la curva E(-1,1) mod ("+cfr.getP()+")\n\n");
        BigInteger msg = BigInteger.valueOf(m);
        int h = (int) Math.floor((cfr.getP().divide(msg.add(BigInteger.valueOf(1)))).intValue());
        BigInteger H = BigInteger.valueOf(h);
        cfr.setH(H);

        //Provo a convertire il messaggio in un punto della curva
        ECPoint mm = null;
        try {
            mm = cfr.koblitz(BigInteger.valueOf(m));
        } catch (NoPointException e) {
            e.printStackTrace();
        }


        System.out.println("Alice trasforma il messaggio m = "+m+" nel punto della curva Pm = ("+mm.getX()+", "+mm.getY()+")\n\n");
        System.out.println("Alice e Bob si accordano sul punto in comune B = ("+B.getX()+", "+B.getY()+")\n");
        //Bob genera una chiave privata [serve per stampare la sua dimensione in bit]
        System.out.println("La lunghezza della chiave è "+prvKey.bitLength()+" bit.\n");

        //Provo a generare una chiave pubblica:
        ECPoint pubKey = null;
        try {
            pubKey = cfr.doubleAndAdd(prvKey,B);
            Pd10 = pubKey;
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }

        System.out.println("La chiave pubblica di Bob è dunque: ("+pubKey.getX()+","+pubKey.getY()+")\n\n");

        Pair<ECPoint, ECPoint> crt = cfr.ECEncrypt(mm,B,pubKey);
        System.out.println("Alice genera quindi il crittogramma crt = {V =("+crt.getKey().getX()+","+crt.getKey().getY()+"); W = ("+crt.getValue().getX()+", "+crt.getValue().getY()+") } e lo spedisce a Bob\n\n");

        return crt;
    }

    public static void RSA_Decrypt(RSA cfr, BigInteger crt){
        System.out.println("Bob riceve crt = "+crt+" e vuole decifrarlo con la sua chiave segreta:\n");
        BigInteger msg = cfr.Decrypt(crt,cfr.getN(),cfr.getD());
        System.out.println("Bob ha decifrato il messaggio che era dunque msg = "+msg+".\n");
    }
    public static void ECC_Decrypt(ECC cfr, BigInteger prvKey, Pair<ECPoint,ECPoint> crt){
        System.out.println("Bob riceve il crittogramma crt = { V = ("+crt.getKey().getX()+", "+crt.getKey().getY()+"); W = ("+crt.getValue().getX()+", "+crt.getValue().getY()+") }\ne vuole decifrarlo con la sua chiave segreta:\n");
        ECPoint mes = cfr.ECDecrypt(crt,prvKey);
        System.out.println("Il punto in cui è contenuto il messaggio è dunque Pm = ("+mes.getX()+", "+mes.getY()+")\n");
        BigInteger msg = cfr.PointToMessage(mes);
        System.out.println("Bob ha decifrato il messaggio che era dunque msg = "+msg+"\n");
    }


    //Funzioni rompi-cifrari
    public static void RSA_Break(RSA cfr, BigInteger crt){
        System.out.println("Provo a fattorizzare n con un attacco enumerativo:\n");
        List<BigInteger> primi = generaPrimi(cfr.getN());
        //Inizio il brute-force
        BigInteger p = BigInteger.valueOf(0),q =  BigInteger.valueOf(0);
        for (BigInteger t:primi) {
            p = cfr.getN().divide(t);
            if((p.multiply(t)).equals(cfr.getN())){
                q = t;
                break;
            }
        }
        System.out.println("La fattorizzazione e' avvenuta con successo e i due numeri primi sono rispettivamente: p = "+p+", q = "+q+".\n\n");
        BigInteger phi = (p.subtract(BigInteger.valueOf(1))).multiply(q.subtract(BigInteger.valueOf(1)));
        BigInteger d = cfr.getE().modInverse(phi);
        System.out.println("Da questi posso dedurre che phi = "+phi+" e dunque posso ricavarmi la chiave privata d = "+d +" dalla quale posso risalire al messaggio m = "+crt.modPow(d,cfr.getN())+"\n\n");
    }

    public static void ECC_Break(ECC cfr,Pair<ECPoint,ECPoint> crt, ECPoint B, ECPoint Pd){
        System.out.println("Provo a calcolare il logaritmo discreto con un attacco enumerativo:\n");
        BigInteger r = BigInteger.valueOf(0);
        for(int k=2;k<cfr.getP().intValue();k++){
            try {
                ECPoint V1 = cfr.doubleAndAdd(BigInteger.valueOf(k),B);
                if(V1.getX().equals(crt.getKey().getX()) && V1.getY().equals(crt.getKey().getY())){
                    r = BigInteger.valueOf(k);
                    break;
                }
            } catch (PointToInfiniteException e) {
                e.printStackTrace();
            }
        }
        //A questo punto ho ricavato r, posso calcolare W = Pm + rPd - rPd, dunque calcolo rPd = r*Pd
        System.out.println("A questo punto sono riuscito a ricavare r = "+r+", dalla quale posso calcolare rPd e dunque calcolare Pm = W - rPd = Pm + rPd - rPd:\n");
        ECPoint Pm = null;
        try {
            ECPoint rPd = cfr.doubleAndAdd(r,Pd);
            Pm = cfr.pointSub(crt.getValue(),rPd);
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }
        BigInteger msg = cfr.PointToMessage(Pm);
        System.out.println("Ho trovato il punto Pm = ("+Pm.getX()+","+Pm.getY()+"). Ora provo ad estrarre il messaggio dal punto della curva:");
        System.out.println("Il logaritmo discreto e' stato svolto con successo, il numero r = "+r+" e il messaggio m = "+msg +".");
    }

    public static void main(String[] args) throws InterruptedException {
        //Cifro e decifro il messaggio 17 con entrambi i cifrari con chiavi a 10 bit e ne calcolo i tempi:
        System.out.println("\nTEST DEI CIFRARI: Cifro e decifro con entrambi i cifrari lo stesso messaggio m='7' usando chiavi a 10 bit per entrambi\n\n");
        //CIFRATURA RSA
        long startRSA1 =  System.nanoTime();
        BigInteger crtRSA10 = RSA_Encrypt(cfrRSA10,m10);
        long endRSA1 = System.nanoTime();
        double RSA1 = endRSA1-startRSA1;
        String RSA1S = String.format("%.3g",0.001*RSA1/1000000);
        System.out.println("Il tempo impiegato per cifrare con RSA a 10 bit è dunque: "+RSA1S+" secondi\n");
        Thread.sleep(3000);

        //DECIFRAZIONE RSA
        long startRSA2 =  System.nanoTime();
        RSA_Decrypt(cfrRSA10, crtRSA10);
        long endRSA2 = System.nanoTime();
        double RSA2 = endRSA2-startRSA2;
        String RSA2S = String.format("%.3g",0.001*RSA2/1000000);
        System.out.println("Il tempo impiegato per decifrare con RSA a 10 bit è dunque: "+RSA2S+" secondi\n\n");
        Thread.sleep(3000);

        //CIFRATURA ECC
        long startECC1 =  System.nanoTime();

        try {
            Pd10 = cfrECC10.doubleAndAdd(prvKey10,B10);
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }

        Pair<ECPoint,ECPoint> crtECC10 = ECC_Encrypt(cfrECC10,m10,B10,prvKey10);

        long endECC1 = System.nanoTime();
        double ECC1 = endECC1-startECC1;
        String ECC1S = String.format("%.3g",0.001*ECC1/1000000);
        System.out.println("Il tempo impiegato per cifrare con ECC a 10 bit è dunque: "+ECC1S+" secondi\n");
        Thread.sleep(3000);


        //DECIFRAZIONE ECC
        long startECC2 =  System.nanoTime();
        ECC_Decrypt(cfrECC10,prvKey10,crtECC10);
        long endECC2 = System.nanoTime();
        double ECC2 = endECC2-startECC2;
        String ECC2S = String.format("%.3g",0.001*ECC2/1000000);
        System.out.println("Il tempo impiegato per decifrare con ECC a 10 bit è dunque: "+ECC2S+" secondi\n");
        Thread.sleep(3000);

        String meglioEn = "ECC";
        String meglioDec = meglioEn;
        if(ECC1 > RSA1) meglioEn = "RSA";
        if(ECC2 > RSA2) meglioDec = "RSA";
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ENCRYPTION/DECRYPTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-10 bit       |        ECC-10 bit     |\n---------------------------------------------------\n|      "+RSA1S+" secondi     |    "+ECC1S+" secondi     | Encryption time ==> "+meglioEn+"\n---------------------------------------------------\n|    "+RSA2S+" secondi      |    "+ECC2S+" secondi    | Decryption time ==> "+meglioDec+"\n---------------------------------------------------\n");

        //TEST ROTTURA RSA
        long startBREAKRSA1 = System.nanoTime();
        RSA_Break(cfrRSA10,crtRSA10);
        long endBREAKRSA1 = System.nanoTime();
        double BRSA1 = endBREAKRSA1-startBREAKRSA1;
        String BRSA1S = String.format("%.3g",0.001*BRSA1/1000000);

        //TEST ROTTURA ECC
        long startBREAKECC1 = System.nanoTime();
        ECC_Break(cfrECC10,crtECC10,B10,Pd10);
        long endBREAKECC1 = System.nanoTime();
        double BECC1 = endBREAKECC1-startBREAKECC1;
        String BECC1S = String.format("%.3g",0.001*BECC1/1000000);

        double rap1 = BECC1/BRSA1;
        String rapp1 =  String.format("%.3g",rap1);
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~BREAK TEST~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-10 bit       |        ECC-10 bit     |\n---------------------------------------------------\n|      "+BRSA1S+" secondi     |    "+BECC1S+" secondi     |\n---------------------------------------------------\n");
        System.out.println("Da ciò si evince che le curve ellittiche sono più sicure dell'RSA con chiavi a 10 bit di circa "+rapp1+" volte.\n\n");



        System.out.println("\nTEST DEI CIFRARI: Cifro e decifro con entrambi i cifrari lo stesso messaggio m='13' usando chiavi a 16 bit per entrambi\n\n");
        //CIFRATURA RSA
        long startRSA3 =  System.nanoTime();
        BigInteger crtRSA16 = RSA_Encrypt(cfrRSA16,m16);
        long endRSA3 = System.nanoTime();
        double RSA3 = endRSA3-startRSA3;
        String RSA3S = String.format("%.3g",0.001*RSA3/1000000);
        System.out.println("Il tempo impiegato per cifrare con RSA a 16 bit è dunque: "+RSA3S+" secondi\n");
        Thread.sleep(3000);

        //DECIFRAZIONE RSA
        long startRSA4 =  System.nanoTime();
        RSA_Decrypt(cfrRSA16,crtRSA16);
        long endRSA4 = System.nanoTime();
        double RSA4 = endRSA4-startRSA4;
        String RSA4S = String.format("%.3g",0.001*RSA4/1000000);
        System.out.println("Il tempo impiegato per decifrare con RSA a 16 bit è dunque: "+RSA4S+" secondi\n\n");
        Thread.sleep(3000);

        //CIFRATURA ECC
        long startECC3 =  System.nanoTime();

        try {
            Pd16 = cfrECC16.doubleAndAdd(prvKey16,B16);
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }

        Pair<ECPoint,ECPoint> crtECC16 = ECC_Encrypt(cfrECC16,m16,B16,prvKey16);
        long endECC3 = System.nanoTime();
        double ECC3 = endECC3-startECC3;
        String ECC3S = String.format("%.3g",0.001*ECC3/1000000);
        System.out.println("Il tempo impiegato per cifrare con ECC a 16 bit è dunque: "+ECC3S+" secondi\n");
        Thread.sleep(3000);


        //DECIFRAZIONE ECC
        long startECC4 =  System.nanoTime();
        ECC_Decrypt(cfrECC16,prvKey16,crtECC16);
        long endECC4 = System.nanoTime();
        double ECC4 = endECC4-startECC4;
        String ECC4S = String.format("%.3g",0.001*ECC4/1000000);
        System.out.println("Il tempo impiegato per decifrare con ECC a 16 bit è dunque: "+ECC4S+" secondi\n");
        Thread.sleep(3000);

        String meglioEn2 = "ECC";
        String meglioDec2 = meglioEn2;
        if(ECC3 > RSA3) meglioEn2 = "RSA";
        if(ECC4 > RSA4) meglioDec2 = "RSA";
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ENCRYPTION/DECRYPTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-16 bit       |        ECC-16 bit     |\n---------------------------------------------------\n|      "+RSA3S+" secondi     |    "+ECC3S+" secondi     | Encryption time ==> "+meglioEn2+"\n---------------------------------------------------\n|    "+RSA4S+" secondi      |    "+ECC4S+" secondi    | Decryption time ==> "+meglioDec2+"\n---------------------------------------------------\n");

        //TEST ROTTURA RSA
        long startBREAKRSA2 = System.nanoTime();
        RSA_Break(cfrRSA16,crtRSA16);
        long endBREAKRSA2 = System.nanoTime();
        double BRSA2 = endBREAKRSA2-startBREAKRSA2;
        String BRSA2S = String.format("%.3g",0.001*BRSA2/1000000);

        //TEST ROTTURA ECC
        long startBREAKECC2 = System.nanoTime();
        ECC_Break(cfrECC16,crtECC16,B16,Pd16);
        long endBREAKECC2 = System.nanoTime();
        double BECC2 = endBREAKECC2-startBREAKECC2;
        String BECC2S = String.format("%.3g",0.001*BECC2/1000000);

        double rap2 = BECC2/BRSA2;
        String rapp2 =  String.format("%.3g",rap2);
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~BREAK TEST~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-16 bit       |        ECC-16 bit     |\n---------------------------------------------------\n|      "+BRSA2S+" secondi     |    "+BECC2S+" secondi     |\n---------------------------------------------------\n");
        System.out.println("Da ciò si evince che le curve ellittiche sono più sicure dell'RSA con chiavi a 16 bit di circa "+rapp2+" volte.\n\n");



        System.out.println("\nTEST DEI CIFRARI: Cifro e decifro con entrambi i cifrari lo stesso messaggio m='19' usando chiavi a 20 bit per entrambi\n\n");
        //CIFRATURA RSA
        long startRSA5 =  System.nanoTime();
        BigInteger crtRSA20 = RSA_Encrypt(cfrRSA20,m20);
        long endRSA5 = System.nanoTime();
        double RSA5 = endRSA5-startRSA5;
        String RSA5S = String.format("%.3g",0.001*RSA5/1000000);
        System.out.println("Il tempo impiegato per cifrare con RSA a 20 bit è dunque: "+RSA5S+" secondi\n");
        Thread.sleep(3000);

        //DECIFRAZIONE RSA
        long startRSA6 =  System.nanoTime();
        RSA_Decrypt(cfrRSA20,crtRSA20);
        long endRSA6 = System.nanoTime();
        double RSA6 = endRSA6-startRSA6;
        String RSA6S = String.format("%.3g",0.001*RSA6/1000000);
        System.out.println("Il tempo impiegato per decifrare con RSA a 20 bit è dunque: "+RSA6S+" secondi\n\n");
        Thread.sleep(3000);

        //CIFRATURA ECC
        long startECC5 =  System.nanoTime();

        try {
            Pd20 = cfrECC20.doubleAndAdd(prvKey20,B20);
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }

        Pair<ECPoint,ECPoint> crtECC20 = ECC_Encrypt(cfrECC20,m20,B20,prvKey20);
        long endECC5 = System.nanoTime();
        double ECC5 = endECC5-startECC5;
        String ECC5S = String.format("%.3g",0.001*ECC5/1000000);
        System.out.println("Il tempo impiegato per cifrare con ECC a 20 bit è dunque: "+ECC5S+" secondi\n");
        Thread.sleep(3000);


        //DECIFRAZIONE ECC
        long startECC6 =  System.nanoTime();
        ECC_Decrypt(cfrECC20,prvKey20,crtECC20);
        long endECC6 = System.nanoTime();
        double ECC6 = endECC6-startECC6;
        String ECC6S = String.format("%.3g",0.001*ECC6/1000000);
        System.out.println("Il tempo impiegato per decifrare con ECC a 20 bit è dunque: "+ECC6S+" secondi\n");
        Thread.sleep(3000);

        String meglioEn3 = "ECC";
        String meglioDec3 = meglioEn3;
        if(ECC5 > RSA5) meglioEn3 = "RSA";
        if(ECC6 > RSA6) meglioDec3 = "RSA";
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ENCRYPTION/DECRYPTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-20 bit       |        ECC-20 bit     |\n---------------------------------------------------\n|      "+RSA5S+" secondi     |    "+ECC5S+" secondi     | Encryption time ==> "+meglioEn3+"\n---------------------------------------------------\n|    "+RSA6S+" secondi      |    "+ECC6S+" secondi    | Decryption time ==> "+meglioDec3+"\n---------------------------------------------------\n");

        //TEST ROTTURA RSA
        long startBREAKRSA3 = System.nanoTime();
        RSA_Break(cfrRSA20,crtRSA20);
        long endBREAKRSA3 = System.nanoTime();
        double BRSA3 = endBREAKRSA3-startBREAKRSA3;
        String BRSA3S = String.format("%.3g",0.001*BRSA3/1000000);

        //TEST ROTTURA ECC
        long startBREAKECC3 = System.nanoTime();
        ECC_Break(cfrECC20,crtECC20,B20,Pd20);
        long endBREAKECC3 = System.nanoTime();
        double BECC3 = endBREAKECC3-startBREAKECC3;
        String BECC3S = String.format("%.3g",0.001*BECC3/1000000);

        double rap3 = BECC3/BRSA3;
        String rapp3 =  String.format("%.3g",rap3);
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~BREAK TEST~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-20 bit       |        ECC-20 bit     |\n---------------------------------------------------\n|      "+BRSA3S+" secondi     |    "+BECC3S+" secondi     |\n---------------------------------------------------\n");
        System.out.println("Da ciò si evince che le curve ellittiche sono più sicure dell'RSA con chiavi a 20 bit di circa "+rapp3+" volte.\n\n");



        System.out.println("\nTEST DEI CIFRARI: Cifro e decifro con entrambi i cifrari lo stesso messaggio m='257' usando chiavi a 24 bit per entrambi\n\n");
        //CIFRATURA RSA
        long startRSA7 =  System.nanoTime();
        BigInteger crtRSA24 = RSA_Encrypt(cfrRSA24,m24);
        long endRSA7 = System.nanoTime();
        double RSA7 = endRSA7-startRSA7;
        String RSA7S = String.format("%.3g",0.001*RSA7/1000000);
        System.out.println("Il tempo impiegato per cifrare con RSA a 24 bit è dunque: "+RSA7S+" secondi\n");
        Thread.sleep(3000);

        //DECIFRAZIONE RSA
        long startRSA8 =  System.nanoTime();
        RSA_Decrypt(cfrRSA24,crtRSA24);
        long endRSA8 = System.nanoTime();
        double RSA8 = endRSA8-startRSA8;
        String RSA8S = String.format("%.3g",0.001*RSA8/1000000);
        System.out.println("Il tempo impiegato per decifrare con RSA a 24 bit è dunque: "+RSA8S+" secondi\n\n");
        Thread.sleep(3000);

        //CIFRATURA ECC
        long startECC7 =  System.nanoTime();

        try {
            Pd24 = cfrECC16.doubleAndAdd(prvKey24,B24);
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }

        Pair<ECPoint,ECPoint> crtECC24 = ECC_Encrypt(cfrECC24,m24,B24,prvKey24);
        long endECC7 = System.nanoTime();
        double ECC7 = endECC7-startECC7;
        String ECC7S = String.format("%.3g",0.001*ECC7/1000000);
        System.out.println("Il tempo impiegato per cifrare con ECC a 24 bit è dunque: "+ECC7S+" secondi\n");
        Thread.sleep(3000);


        //DECIFRAZIONE ECC
        long startECC8 =  System.nanoTime();
        ECC_Decrypt(cfrECC24,prvKey24,crtECC24);
        long endECC8 = System.nanoTime();
        double ECC8 = endECC8-startECC8;
        String ECC8S = String.format("%.3g",0.001*ECC8/1000000);
        System.out.println("Il tempo impiegato per decifrare con ECC a 24 bit è dunque: "+ECC8S+" secondi\n");
        Thread.sleep(3000);

        String meglioEn4 = "ECC";
        String meglioDec4 = meglioEn4;
        if(ECC7 > RSA7) meglioEn4 = "RSA";
        if(ECC8 > RSA8) meglioDec4 = "RSA";
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ENCRYPTION/DECRYPTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-24 bit       |        ECC-24 bit     |\n---------------------------------------------------\n|      "+RSA7S+" secondi     |    "+ECC7S+" secondi     | Encryption time ==> "+meglioEn4+"\n---------------------------------------------------\n|    "+RSA8S+" secondi      |    "+ECC8S+" secondi    | Decryption time ==> "+meglioDec4+"\n---------------------------------------------------\n");

        //TEST ROTTURA RSA
        long startBREAKRSA4 = System.nanoTime();
        RSA_Break(cfrRSA24,crtRSA24);
        long endBREAKRSA4 = System.nanoTime();
        double BRSA4 = endBREAKRSA4-startBREAKRSA4;
        String BRSA4S = String.format("%.3g",0.001*BRSA4/1000000);

        //TEST ROTTURA ECC
        long startBREAKECC4 = System.nanoTime();
        ECC_Break(cfrECC24,crtECC24,B24,Pd24);
        long endBREAKECC4 = System.nanoTime();
        double BECC4 = endBREAKECC4-startBREAKECC4;
        String BECC4S = String.format("%.3g",0.001*BECC4/1000000);

        double rap4 = BECC4/BRSA4;
        String rapp4 =  String.format("%.3g",rap4);
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~BREAK TEST~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-24 bit       |        ECC-24 bit     |\n---------------------------------------------------\n|      "+BRSA4S+" secondi     |    "+BECC4S+" secondi     |\n---------------------------------------------------\n");
        System.out.println("Da ciò si evince che le curve ellittiche sono più sicure dell'RSA con chiavi a 24 bit di circa "+rapp4+" volte.\n\n");



        System.out.println("\nTEST DEI CIFRARI: Cifro e decifro con entrambi i cifrari lo stesso messaggio m='251' usando chiavi a 25 bit per entrambi\n\n");
        //CIFRATURA RSA
        long startRSA9 =  System.nanoTime();
        BigInteger crtRSA25 = RSA_Encrypt(cfrRSA25,m25);
        long endRSA9 = System.nanoTime();
        double RSA9 = endRSA9-startRSA9;
        String RSA9S = String.format("%.3g",0.001*RSA9/1000000);
        System.out.println("Il tempo impiegato per cifrare con RSA a 25 bit è dunque: "+RSA9S+" secondi\n");
        Thread.sleep(3000);

        //DECIFRAZIONE RSA
        long startRSA10 =  System.nanoTime();
        RSA_Decrypt(cfrRSA25,crtRSA25);
        long endRSA10 = System.nanoTime();
        double RSA10 = endRSA10-startRSA10;
        String RSA10S = String.format("%.3g",0.001*RSA10/1000000);
        System.out.println("Il tempo impiegato per decifrare con RSA a 25 bit è dunque: "+RSA10S+" secondi\n\n");
        Thread.sleep(3000);

        //CIFRATURA ECC
        long startECC9 =  System.nanoTime();

        try {
            Pd25 = cfrECC25.doubleAndAdd(prvKey25,B25);
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }

        Pair<ECPoint,ECPoint> crtECC25 = ECC_Encrypt(cfrECC25,m25,B25,prvKey25);
        long endECC9 = System.nanoTime();
        double ECC9 = endECC9-startECC9;
        String ECC9S = String.format("%.3g",0.001*ECC9/1000000);
        System.out.println("Il tempo impiegato per cifrare con ECC a 25 bit è dunque: "+ECC9S+" secondi\n");
        Thread.sleep(3000);


        //DECIFRAZIONE ECC
        long startECC10 =  System.nanoTime();
        ECC_Decrypt(cfrECC25,prvKey25,crtECC25);
        long endECC10 = System.nanoTime();
        double ECC10 = endECC10-startECC10;
        String ECC10S = String.format("%.3g",0.001*ECC10/1000000);
        System.out.println("Il tempo impiegato per decifrare con ECC a 25 bit è dunque: "+ECC10S+" secondi\n");
        Thread.sleep(3000);

        String meglioEn5 = "ECC";
        String meglioDec5 = meglioEn5;
        if(ECC9 > RSA9) meglioEn5 = "RSA";
        if(ECC10 > RSA10) meglioDec5 = "RSA";
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ENCRYPTION/DECRYPTION~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-25 bit       |        ECC-25 bit     |\n---------------------------------------------------\n|      "+RSA9S+" secondi     |    "+ECC9S+" secondi     | Encryption time ==> "+meglioEn5+"\n---------------------------------------------------\n|    "+RSA10S+" secondi      |    "+ECC10S+" secondi    | Decryption time ==> "+meglioDec5+"\n---------------------------------------------------\n");

        //TEST ROTTURA RSA
        long startBREAKRSA5 = System.nanoTime();
        RSA_Break(cfrRSA25,crtRSA25);
        long endBREAKRSA5 = System.nanoTime();
        double BRSA5 = endBREAKRSA5-startBREAKRSA5;
        String BRSA5S = String.format("%.3g",0.001*BRSA5/1000000);

        //TEST ROTTURA ECC
        long startBREAKECC5 = System.nanoTime();
        ECC_Break(cfrECC25,crtECC25,B25,Pd25);
        long endBREAKECC5 = System.nanoTime();
        double BECC5 = endBREAKECC5-startBREAKECC5;
        BECC5 = BECC5/60;
        String BECC5S = String.format("%.3g",0.001*BECC5/1000000);

        double rap5 = BECC5*60/BRSA5;
        String rapp5 =  String.format("%.3g",rap5);
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~BREAK TEST~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|        RSA-25 bit       |        ECC-25 bit     |\n---------------------------------------------------\n|      "+BRSA5S+" secondi     |    "+BECC5S+" minuti     |\n---------------------------------------------------\n");
        System.out.println("Da ciò si evince che le curve ellittiche sono più sicure dell'RSA con chiavi a 25 bit di circa "+rapp5+" volte.\n\n");



    }

    public static List<BigInteger> generaPrimi(BigInteger n) {
        List<BigInteger> primi = new LinkedList<>();
        if(n.intValue() >= 2) {
            primi.add(BigInteger.valueOf(2));
        }
        for(int i = 3; i <= n.intValue(); i += 2) {
            if (isPrime(BigInteger.valueOf(i))) {
                primi.add(BigInteger.valueOf(i));
            }
        }
        return primi;
    }
    private static boolean isPrime(BigInteger number) {
        for (int i = 2; i*i < number.intValue(); i++)
            if (number.intValue() % i == 0)
                return false;
        return true;
    }
}
