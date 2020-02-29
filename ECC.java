import Exceptions.NoPointException;
import Exceptions.PointToInfiniteException;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.Random;

public class ECC {
    //variabili d'istanza (y^2)mod(p) = (x^3 + ax + b)mod(p)
    private BigInteger a;
    private BigInteger b;
    private BigInteger p;
    private BigInteger h;

    public ECC(BigInteger A, BigInteger B, BigInteger P){
        a = A;
        b = B;
        p = P;
    }

    public BigInteger getP(){
        return p;
    }

    public BigInteger getA(){
        return a;
    }

    public BigInteger getB() {
        return b;
    }

    public BigInteger getH(){  return h; }
    public void setH(BigInteger h1){h = h1;}
    //Controlla che y sia residuo quadratico
    private boolean residuoQuadratico(BigInteger z){
        z = z.mod(getP());
        BigInteger exp = getP().subtract(BigInteger.valueOf(1)).divide(BigInteger.valueOf(2));
        // a è residuo quadratico modulo p se a^(p-1)/2 = 1 mod p
        return z.modPow(exp,getP()).compareTo(BigInteger.valueOf(1)) == 0;
    }


    //genera un punto nella curva con alta probabilità (1-(1/2)^h)
    public ECPoint koblitz(BigInteger m) throws NoPointException {
        for(int i=0;i<getH().intValue();i++){
            BigInteger x = (m.multiply(getH()).add(BigInteger.valueOf(i))).mod(getP());
            BigInteger z = (x.multiply(x).multiply(x).add(getA().multiply(x)).add(getB())).mod(getP());
            //è residuo quadratico?
            if(residuoQuadratico(z)){
                return new ECPoint(getA(),getB(),getP(),x,(z.sqrt()).mod(getP()));
            }
        }
        throw new NoPointException("Non è stato generato un punto nella curva");
    }
    //Trasforma un punto nella curva in un messaggio
    public BigInteger PointToMessage(ECPoint Pm){
        int m = (int)Math.floor((Pm.getX().divide(getH()).intValue()));
        return BigInteger.valueOf(m);
    }
    //SOMMA DUE PUNTI DISTINTI
    public ECPoint pointAdd(ECPoint P, ECPoint Q)  throws PointToInfiniteException{
        //escludere xQ = xP
        if(P.getX().equals(Q.getX())) throw new PointToInfiniteException("Il punto che è stato generato è un punto all'infinito; non può essere usato per cifrare");
        //lambda = (yQ-yP)*(xQ-xP)^-1 mod p
        BigInteger lambda = ((Q.getY().subtract(P.getY())).multiply((Q.getX().subtract(P.getX())).modInverse(getP()))).mod(getP());
        //xS = lambda^2 - xP - xQ
        BigInteger xS = (lambda.multiply(lambda).subtract(P.getX()).subtract(Q.getX())).mod(getP());
        //yS = -yP + lambda(x1 - xS)
        BigInteger yS = (P.getY().multiply(BigInteger.valueOf(-1)).add(lambda.multiply(P.getX().subtract(xS)))).mod(getP());

        return new ECPoint(getA(),getB(),getP(),xS,yS);
    }

    //SOTTRAZIONE TRA DUE PUNTI DISTINTI
    public ECPoint pointSub(ECPoint P, ECPoint Q){

        ECPoint Q1 = new ECPoint(getA(),getB(),getP(),Q.getX(), Q.getY().multiply(BigInteger.valueOf(-1)));
        try {
            return pointAdd(P,Q1);
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }
        return null;
    }
    //SOMMA DI PUNTI UGUALI
    public ECPoint doublePoint(ECPoint P) throws PointToInfiniteException {
        //VANNO ESCLUSI I PUNTI CON y = 0 se da raddoppiare
        if(P.getY().equals(BigInteger.valueOf(0))) throw new PointToInfiniteException("Il punto che è stato generato è un punto all'infinito; non può essere usato per cifrare");
        //lambda = (3xP + a)*(2yP)^-1 mod p
        BigInteger lambda = (BigInteger.valueOf(3).multiply((P.getX()).pow(2)).add(getA()).multiply((BigInteger.valueOf(2).multiply(P.getY())).modInverse(getP()))).mod(getP());
        //xS = lambda^2 - 2*xP
        BigInteger xS = (lambda.pow(2).subtract(BigInteger.valueOf(2).multiply(P.getX()))).mod(getP());
        //yS = -yP + lambda(xP-xS)
        BigInteger yS = (BigInteger.valueOf(-1).multiply((P.getY().add(lambda.multiply((xS.subtract(P.getX()))))))).mod(getP());

        return new ECPoint(getA(),getB(),getP(),xS,yS);
    }

    public ECPoint doubleAndAdd(BigInteger rIn, ECPoint A) throws PointToInfiniteException {
        BigInteger r = rIn.mod(getP());
        int l = r.bitLength();
        if (l != 0){
            ECPoint R = A;
            for (int i = l-2;i>=0;--i){
                try {
                    R = doublePoint(R);
                } catch (PointToInfiniteException e) {
                    e.printStackTrace();
                }
                if(r.testBit(i)){
                    try {
                        R = pointAdd(R,A);
                    } catch (PointToInfiniteException e) {
                        e.printStackTrace();
                    }
                }
            }
            return R;
        }
        throw new PointToInfiniteException("Il punto che è stato generato è un punto all'infinito; non può essere usato per cifrare");
    }
    public Pair<ECPoint,ECPoint> ECEncrypt(ECPoint Pm, ECPoint B, ECPoint pubKey){
        Random c = new Random();

        int rIn = c.nextInt((((getP().subtract(BigInteger.valueOf(5))).intValue()) - 7) + 1 ) + 7;

        //Devo generare V = rB
        BigInteger r = BigInteger.valueOf(rIn);
        ECPoint V = null;
        try {
            V = doubleAndAdd(r,B);
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }
        //GENERO W = Pm + rPd
        ECPoint rPd = null;
        try {
            rPd = doubleAndAdd(r,pubKey);
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }
        ECPoint W = null;
        if(rPd == null) throw new NullPointerException();
        try {
            W = pointAdd(Pm,rPd);
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }

        return new Pair<>(V,W);
    }

    public ECPoint ECDecrypt(Pair<ECPoint,ECPoint> crt, BigInteger prvKey){
        ECPoint ndV = null;
        try {
            ndV = doubleAndAdd(prvKey,crt.getKey());
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }
        ECPoint W = crt.getValue();
        if(ndV == null) throw new NullPointerException();
        return pointSub(W,ndV);
    }
}
