namespace Glycin.Analysis;

using Glycin.DataModel;
using Iced.Intel;

public abstract class VectorScanner
{
    /*
     * this is not magic. it's arbitrary.
     *
     * to future V:
     *  - expand if they fuck with the encryption again.
     */
    protected const int AnalysisWindowWidth = 64;
    
    protected ExecutableInfo ExecutableInfo { get; }

    protected VectorScanner(ExecutableInfo executableInfo)
    {
        ExecutableInfo = executableInfo;   
    }

    public abstract List<DecryptionVector> Scan(List<Instruction> insns);
}