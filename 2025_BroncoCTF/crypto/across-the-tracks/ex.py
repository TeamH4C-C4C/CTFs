ct = "Samddre··ath·dhf@_oesoere·ebun·yhot·no··oso·i·a·lr1rcm·iS·aruf·toibadhn·nadpikudynea{l_oeee·ch·oide·f·n·aoe·sae·aonbdhgo_so·rr.i·tYnl·s·tdot·xs·hdtyy'·.t·cfrlca·epeo·iufiyi.t·yaaf·.a.·ts··tn33}i·tvhr·.tooho···rlmwuI·h·e·iHshonppsoleaseecrtudIdet.·n·BtIpdheiorcihr·or·ovl·c··i·acn·t·su··ootr·:b3cesslyedheIath·e·_"

length = len(ct)
rail = [[' ' for i in range(length)] for j in range(10)]

down = True
height = 0
for i in range(length):
    if height == 0:
        down = True
    elif height == 9:
        down = False
    
    rail[height][i] = 'v'
    if down:
        height += 1
    else:
        height -= 1

idx = 0
exitflag = False
for i in range(10):
    for j in range(length):
        if rail[i][j] == 'v':
            rail[i][j] = ct[idx]
            idx += 1
            if idx == length:
                exitflag = True
                break
    if exitflag:
        break

down = True
height = 0
for i in range(length):
    if height == 0:
        down = True
    elif height == 9:
        down = False
    
    print(rail[height][i], end='')
    if down:
        height += 1
    else:
        height -= 1
print()