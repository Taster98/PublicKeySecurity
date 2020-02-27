import Exceptions.NoPointException;
import Exceptions.PointToInfiniteException;
import javafx.util.Pair;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import java.math.BigInteger;

public class TestMain {
    public static void testECC(){
        System.out.println("TEST CIFRATURA CON CURVE ELLITTICHE PRIME: (chiave a 10 bit)\n");
        System.out.println("Il mittente Mitt prova a cifrare il messaggio intero '17' con la curva ellittica prima E(-1,1)mod(1301)");
        System.out.println("Genero tutti i punti della curva:");

        ECC curva = new ECC(BigInteger.valueOf(-1),BigInteger.valueOf(1),BigInteger.valueOf(1301));

        for(ECPoint a : curva.getCurve()){
            System.out.println("("+ a.getX()+", "+a.getY()+")");
        }

        System.out.println("Il numero totale dei punti della curva è: "+curva.getCurve().size()+"\n\n");

        int m = 17;
        int h = (int) Math.floor((curva.getP().divide(BigInteger.valueOf(m).add(BigInteger.valueOf(1)))).intValue());
        ECPoint msg = null;
        try {
            msg = curva.koblitz(BigInteger.valueOf(m),h);
        } catch (NoPointException e) {
            e.printStackTrace();
        }

        System.out.println("Trasformo il messaggio "+m+" nel punto nella curva ("+msg.getX()+", "+msg.getY()+") con l'algoritmo di Koblitz\n");

        ECPoint B = new ECPoint(curva,BigInteger.valueOf(630),BigInteger.valueOf(1275));
        System.out.println("Viene ora generato un punto della curva a caso sulla quale i due interlocutori si mettono d'accordo\n per avviare il protocollo per lo scambio dei messaggi di El Gamal, ad esempio B = ("+B.getX()+","+B.getY()+")\n\n");
        System.out.println("Il destinatario si sceglie una chiave privata (in questo caso di 10 bit), con la quale poi creerà la chiave pubblica");
        BigInteger prvKey = BigInteger.valueOf(1000);

        ECPoint pubKey = null;
        try {
            pubKey = curva.doubleAndAdd(prvKey,B);
        } catch (PointToInfiniteException e) {
            e.getMessage();
        }
        System.out.println("La chiave pubblica così generata è dunque: ("+pubKey.getX()+","+pubKey.getY()+")\n\n");
        Pair<ECPoint, ECPoint> crt = curva.ECEncrypt(msg,B,pubKey);
        System.out.println("Il mittente Mitt crea quindi il crittogramma con il metodo di cifratura, per spedirlo al destinatario: crt = ("+crt.getValue().getX()+","+crt.getValue().getY()+")\n\n");
        System.out.println("Il destinatario Dest riceve quindi la coppia di punti: ("+crt.getKey().getX()+","+crt.getKey().getY()+"), ("+crt.getValue().getX()+","+crt.getValue().getY()+")\n");
        ECPoint dcrt = curva.ECDecrypt(crt,prvKey);
        System.out.println("Il destinatario con l'opportuna funzione di decifrazione decifra con la sua chiave privata il messaggio, che è salvato nel punto: ("+dcrt.getX()+","+dcrt.getY()+")");
        BigInteger messaggioFinale = curva.PointToMessage(dcrt,BigInteger.valueOf(h));
        System.out.println("E il messaggio originale era dunque: "+messaggioFinale);
    }

    public static void testRSA(){
        System.out.println("TEST CIFRATURA CON RSA: (chiave a 10 bit) \n");
        RSA cifrario = new RSA(BigInteger.valueOf(67),BigInteger.valueOf(89));
        System.out.println("Il mittente Mitt prova a cifrare il messaggio '17' con i dati e = "+ cifrario.getE() + ", n = "+cifrario.getN());
        BigInteger msg = BigInteger.valueOf(17);
        BigInteger crt = cifrario.Encrypt(msg,cifrario.getN(),cifrario.getE());
        System.out.println("Il messaggio diventa ora crt = " + crt);
        System.out.println("Il destinatario riceve crt = "+ crt + " e prova a decifrarlo con la sua chiave privata:");
        BigInteger dcrt = cifrario.Decrypt(crt,cifrario.getN(),cifrario.getD());
        System.out.println("Il messaggio originale era: "+ dcrt);
    }
    public static void testRSA_Security(){
        //Ora provo a violare RSA con un attacco enumerativo sulle chiavi (fattorizzo n)
        System.out.println("Provo ora a fattorizzarre n con un attacco enumerativo:");

        long startTime = System.nanoTime();
        RSA cifrario = new RSA(BigInteger.valueOf(1301),BigInteger.valueOf(7753));
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
        System.out.println("La fattorizzazione è avvenuta con successo in "+String.format("%.3g",0.001*timeelapsed/1000000) + " secondi, e i due numeri primi sono rispettivamente: p = "+p+", q = "+q+".");
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
    public static void main(String[] args){
        //Lancio il test sulla cifratura con curve ellittiche
        //testECC();

        //Lancio il test sulla cifratura con RSA
        //testRSA();
        //Lancio il test sulla rottura del cifrario RSA
        testRSA_Security();
        //Lancio il test sulla rottura del cifrario su curve ellittiche prime
    }
}
