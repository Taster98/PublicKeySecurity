import Exceptions.NoPointException;
import Exceptions.PointToInfiniteException;
import javafx.util.Pair;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import java.math.BigInteger;

public class TestMain {
    private static long startTime = System.nanoTime();
    private static ECC curva = new ECC(BigInteger.valueOf(-1),BigInteger.valueOf(1),BigInteger.valueOf(10427));
    private static RSA cifrario = new RSA(BigInteger.valueOf(137),BigInteger.valueOf(79));
    private static BigInteger crittoRSA;
    private static Pair<ECPoint,ECPoint> crittoECC;
    private static ECPoint Bb;
    private static ECPoint Pd;
    private static BigInteger H;
    public static void testECC(){
        System.out.println("TEST CIFRATURA CON CURVE ELLITTICHE PRIME: (chiave a ~10 bit)\n");
        System.out.println("Il mittente Mitt prova a cifrare il messaggio intero '17' con la curva ellittica prima E(-1,1)mod(10427)\n\n");
        //System.out.println("Genero tutti i punti della curva:");
        /*for(ECPoint a : curva.getCurve()){
            System.out.println("("+ a.getX()+", "+a.getY()+")");
        }*/

        System.out.println("Il numero totale dei punti della curva è: "+curva.getCurve().size()+"\n\n");

        int m = 17;
        int h = (int) Math.floor((curva.getP().divide(BigInteger.valueOf(m).add(BigInteger.valueOf(1)))).intValue());
        H = BigInteger.valueOf(h);
        ECPoint msg = null;
        try {
            msg = curva.koblitz(BigInteger.valueOf(m),h);
        } catch (NoPointException e) {
            e.printStackTrace();
        }
        System.out.println("Trasformo il messaggio "+m+" nel punto nella curva ("+msg.getX()+", "+msg.getY()+") con l'algoritmo di Koblitz\n\n");
        ECPoint B = new ECPoint(curva,BigInteger.valueOf(3188),BigInteger.valueOf(10374));
        Bb = B;
        System.out.println("Viene ora generato un punto della curva a caso sulla quale i due interlocutori si mettono d'accordo\n per avviare il protocollo per lo scambio dei messaggi di El Gamal, ad esempio B = ("+B.getX()+","+B.getY()+")\n\n");
        System.out.println("Il destinatario si sceglie una chiave privata (in questo caso di ~10 bit), con la quale poi creerà la chiave pubblica\n\n");
        //Genero una chiave di 23 bit
        //BigInteger prvKey = BigInteger.valueOf(5779567);
        BigInteger prvKey = BigInteger.valueOf(7817);

        System.out.println("La lunghezza della chiave è: ~"+prvKey.bitLength()+" bit");
        ECPoint pubKey = null;
        try {
            pubKey = curva.doubleAndAdd(prvKey,B);
            Pd = pubKey;
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }
        System.out.println("La chiave pubblica così generata è dunque: ("+pubKey.getX()+","+pubKey.getY()+")\n\n");
        Pair<ECPoint, ECPoint> crt = curva.ECEncrypt(msg,B,pubKey);
        crittoECC = crt;
        System.out.println("Il mittente Mitt crea quindi il crittogramma con il metodo di cifratura, per spedirlo al destinatario: crt = ("+crt.getValue().getX()+","+crt.getValue().getY()+")\n\n");
        System.out.println("Il destinatario Dest riceve quindi la coppia di punti: V = ("+crt.getKey().getX()+","+crt.getKey().getY()+"), W = ("+crt.getValue().getX()+","+crt.getValue().getY()+")\n\n");
        ECPoint dcrt = curva.ECDecrypt(crt,prvKey);
        System.out.println("Il destinatario con l'opportuna funzione di decifrazione decifra con la sua chiave privata il messaggio, che è salvato nel punto: Pm = ("+dcrt.getX()+","+dcrt.getY()+")\n\n");
        BigInteger messaggioFinale = curva.PointToMessage(dcrt,BigInteger.valueOf(h));
        System.out.println("Il messaggio originale era dunque: "+messaggioFinale+"\n");
    }

    public static void testRSA(){
        System.out.println("TEST CIFRATURA CON RSA: (chiave a ~10 bit) \n\n");
        System.out.println("Il mittente Mitt prova a cifrare il messaggio '17' con i dati e = "+ cifrario.getE() + ", n = "+cifrario.getN());
        BigInteger msg = BigInteger.valueOf(17);
        System.out.println("\n\nLa lunghezza della chiave è: "+cifrario.getD().bitLength()+" bits\n\n");
        BigInteger crt = cifrario.Encrypt(msg,cifrario.getN(),cifrario.getE());
        System.out.println("Il messaggio diventa ora crt = " + crt);
        crittoRSA = crt;
        System.out.println("\n\nIl destinatario riceve crt = "+ crt + " e prova a decifrarlo con la sua chiave privata:\n\n");
        BigInteger dcrt = cifrario.Decrypt(crt,cifrario.getN(),cifrario.getD());
        System.out.println("Il messaggio originale era: "+ dcrt);
    }
    public static double testRSA_Security(){
        //Ora provo a violare RSA con un attacco enumerativo sulle chiavi (fattorizzo n)
        System.out.println("\n\nATTACCO AL CIFRARIO RSA\n\n");
        System.out.println("\n\nProvo ora a fattorizzarre n con un attacco enumerativo:\n");

        long startTime = System.nanoTime();
        //Genero per prima cosa tutti i numeri primi più piccoli di n, poi provo a dividere per ciascuno di loro fino a che non trovo quelli che fattorizzino n:
        List<BigInteger> primi = generaPrimi(cifrario.getN());
        //Inizio il brute-force
        BigInteger p = BigInteger.valueOf(0);
        BigInteger q = BigInteger.valueOf(0);
        for (BigInteger t:primi) {
            p = cifrario.getN().divide(t);
            if((p.multiply(t)).equals(cifrario.getN())){
                q = t;
                break;
            }
        }
        long endTime = System.nanoTime();
        double timeelapsed = endTime-startTime;
        System.out.println("La fattorizzazione è avvenuta con successo in "+String.format("%.3g",0.001*timeelapsed/1000000) + " secondi, e i due numeri primi sono rispettivamente: p = "+p+", q = "+q+".\n\n");
        BigInteger phi = (p.subtract(BigInteger.valueOf(1))).multiply(q.subtract(BigInteger.valueOf(1)));
        BigInteger d = cifrario.getE().modInverse(phi);
        System.out.println("Da questi posso dedurre che phi = "+phi+" e dunque posso ricavarmi la chiave privata d = "+d +" dalla quale posso risalire al messaggio m = "+crittoRSA.modPow(d,cifrario.getN())+"\n\n");
        return timeelapsed;
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
        for (int i = 2; i*i < number.intValue(); i++) {
            if (number.intValue() % i == 0) {
                return false;
            }
        }
        return true;
    }

    public static double testECC_security(){
        long startTime = System.nanoTime();
        System.out.println("ATTACCO AL CIFRARIO SU CURVE ELLITTICHE:\n");
        System.out.println("Provo a calcolare il logaritmo discreto per la curva per poter ricavare r.\n");
        BigInteger r = BigInteger.valueOf(0);
        for(int k=2;k<curva.getP().intValue();k++){
            try {
                ECPoint V1 = curva.doubleAndAdd(BigInteger.valueOf(k),Bb);
                if(V1.getX().equals(crittoECC.getKey().getX()) && V1.getY().equals(crittoECC.getKey().getY())){
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
            ECPoint rPd = curva.doubleAndAdd(r,Pd);
            Pm = curva.pointSub(crittoECC.getValue(),rPd);
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }
        BigInteger msg = curva.PointToMessage(Pm,H);
        System.out.println("Ho trovato il punto Pm = ("+Pm.getX()+","+Pm.getY()+"). Ora provo ad estrarre il messaggio dal punto della curva:");

        long endTime = System.nanoTime();
        double timeelapsed = endTime-startTime;
        System.out.println("Il logaritmo discreto è stato svolto con successo in "+String.format("%.3g",0.001*timeelapsed/1000000) + " secondi, il numero r = "+r+" e il messaggio m = "+msg +".");
        return timeelapsed;
    }

    public static void main(String[] args){
        //Lancio il test sulla cifratura con curve ellittiche

        testECC();
        long endTime = System.nanoTime();
        double timeelapsed = endTime-startTime;
        System.out.println("Il messaggio è stato cifrato in "+String.format("%.3g",0.001*timeelapsed/1000000) + " secondi.\n\n\n");
        //Lancio il test sulla rottura del cifrario su curve ellittiche prime
        //Voglio rompere la crittografia su curve ellittiche, come?
        //So che il cifrario funziona così: Pd e B sono pubbliche, viene generato a caso r e dunque V = rB e W = Pm + rPd
        //Quindi se trovo r posso calcolare W = Pm + rPd - rPd = Pm. Da qui posso calcolare m.
        //Come faccio? Prendo la base e provo a moltiplicare per r casuali fino a che kB = rB ovvero k=r, let's go!
        double t1 = testECC_security();
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        //Lancio il test sulla cifratura con RSA
        testRSA();
        //Lancio il test sulla rottura del cifrario RSA
        double t2 = testRSA_Security();
        String s1 = String.format("%.3g",0.001*t2/1000000);
        String s2 = String.format("%.3g",0.001*t1/1000000);
        System.out.println("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n");
        System.out.println("---------------------------------------------------\n|     Fattorizzazione     |   Logaritmo Discreto   |\n---------------------------------------------------\n|     "+s1+" secondi       |    "+s2+" secondi    |\n---------------------------------------------------\n");
        int n = (int) ((int) t1/t2);
        System.out.println("Da ciò si evince che la fattorizzazione richieda circa "+n+" volte meno tempo rispetto alla risoluzione del logaritmo discreto su curve ellittiche a parità di chiave\n\nFINE");
    }
}
