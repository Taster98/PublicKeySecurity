import Exceptions.NoPointException;
import Exceptions.PointToInfiniteException;
import javafx.util.Pair;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class ECC {

    BigInteger a;
    BigInteger b;
    BigInteger p;
    //insieme dei punti
    List<ECPoint> curve;

    public ECC(BigInteger A, BigInteger B, BigInteger P){
        a = A;
        b = B;
        p = P;
        curve = generaPunti();
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
    //Controlla che y sia residuo quadratico
    public boolean residuoQuadratico(BigInteger x, BigInteger y){
        List<ECPoint> pnts = getCurve();
        for(ECPoint px : pnts){
           if(y.equals(px.getY()) && x.equals(px.getX())){
               return true;
           }
        }
        return false;
    }


    //genera un punto nella curva con alta probabilità (1-(1/2)^h)
    public ECPoint koblitz(BigInteger m, int h) throws NoPointException {

        //Se il messaggio è 7, h: 8*h < 67 => h<67/8 => h=8
        for(int i=0;i<h;i++){
            BigInteger x = (m.multiply(BigInteger.valueOf(h)).add(BigInteger.valueOf(i))).mod(getP());
            BigInteger z = (x.multiply(x).multiply(x).add(getA().multiply(x)).add(getB())).mod(getP());
            //è residuo quadratico?
            if(residuoQuadratico(x,z.sqrt())){
                return new ECPoint(getA(),getB(),getP(),x,z.sqrt());
            }
        }
        throw new NoPointException("Non è stato generato un punto nella curva");
    }
    //genera tutti i punti della curva
    public ArrayList<ECPoint> generaPunti(){
        ArrayList<ECPoint> punti = new ArrayList<>();
        for(int i=0;i<getP().intValue();i++){
            for(int j=0;j<getP().intValue();j++){
                BigInteger yq = (BigInteger.valueOf(i).multiply(BigInteger.valueOf(i))).mod(getP());
                BigInteger xe = (BigInteger.valueOf(j).multiply(BigInteger.valueOf(j)).multiply(BigInteger.valueOf(j)).add(getA().multiply(BigInteger.valueOf(j))).add(getB())).mod(getP());
                if(yq.equals(xe)){
                    punti.add(new ECPoint(getA(),getB(),getP(),BigInteger.valueOf(j),BigInteger.valueOf(i)));
                }
            }
        }
        return punti;
    }

    public List<ECPoint> getCurve() {
        return curve;
    }
    //escludere xQ = xP
    public ECPoint pointAdd(ECPoint P, ECPoint Q)  throws PointToInfiniteException{
        //SOMMA DUE PUNTI DISTINTI
        if(P.getX().equals(Q.getX())) throw new PointToInfiniteException("Il punto che è stato generato è un punto all'infinito; non può essere usato per cifrare");
        //lambda = (yQ-yP)*(xQ-xP)^-1 mod p
        BigInteger lambda = ((Q.getY().subtract(P.getY())).multiply((Q.getX().subtract(P.getX())).modInverse(getP()))).mod(getP());
        //xS = lambda^2 - xP - xQ
        BigInteger xS = (lambda.multiply(lambda).subtract(P.getX()).subtract(Q.getX())).mod(getP());
        //yS = -yP + lambda(x1 - xS)
        BigInteger yS = (P.getY().multiply(BigInteger.valueOf(-1)).add(lambda.multiply(P.getX().subtract(xS)))).mod(getP());

        return new ECPoint(getA(),getB(),getP(),xS,yS);
    }

    public ECPoint pointSub(ECPoint P, ECPoint Q){
        //SOTTRAZIONE TRA DUE PUNTI DISTINTI
        ECPoint Q1 = new ECPoint(getA(),getB(),getP(),Q.getX(), Q.getY().multiply(BigInteger.valueOf(-1)));
        try {
            return pointAdd(P,Q1);
        } catch (PointToInfiniteException e) {
            e.printStackTrace();
        }
        return null;
    }
    //VANNO ESCLUSI I PUNTI CON y = 0 se da raddoppiare
    public ECPoint doublePoint(ECPoint P) throws PointToInfiniteException {
        //SOMMA DI PUNTI UGUALI
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

        int rIn = c.nextInt((((getP().subtract(BigInteger.valueOf(5))).intValue()) - 600) + 1 ) + 600;

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

        return pointSub(W,ndV);
    }

    public BigInteger PointToMessage(ECPoint Pm, BigInteger h){
        int m = (int)Math.floor((Pm.getX().divide(h).intValue()));
        return BigInteger.valueOf(m);
    }
}
