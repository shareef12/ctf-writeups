# What's The Frequency, Kenneth? - Points: 50 - (Solves: 300)

**Category**: Cryptography

**Description**: A local historical society has uncovered an encrypted message
behind a picture in Philidelphia. Break the code to find the message and the
flag at `challenge.acictf.com:28900`. Example connection command:
`nc challenge.acictf.com 28900`

**Hints**:
- Special characters and white space are preserved in this monoalphabetic
  cipher
- What are the most common and uncommon letters? How does it compare to an
  english work like 'Alice in Wonderland'
  (https://www.gutenberg.org/files/11/11-h/11-h.htm)?
- What about the frequency of pairs or triples of letters? How do they compare?

## Solution

Based on the challenge name and hints, it appears this is problem is probably a
simple substitution cipher. Connecting the the service shows that it is
non-interactive. It prints the ciphertext and exits.

```
$ nc challenge.acictf.com 28900
The encrypted message:

Jeu abzbxnoar Iutmzgzjxob oh jeu jexgjuub abxjui Rjzjur oh Znugxtz, Leub xb jeu Toagru oh eanzb uvubjr, xj yutonur buturrzgd hog obu wuowmu jo ixrromvu jeu womxjxtzm yzbir lexte ezvu tobbutjui jeun lxje zbojeug, zbi jo zrranu znobk jeu wolugr oh jeu uzgje, jeu ruwzgzju zbi uqazm rjzjxob jo lexte jeu Mzlr oh Bzjagu zbi oh Bzjagu'r Koi ubjxjmu jeun, z iutubj gurwutj jo jeu owxbxobr oh nzbpxbi guqaxgur jezj jeud reoami iutmzgu jeu tzarur lexte xnwum jeun jo jeu ruwzgzjxob.

Lu eomi jeuru jgajer jo yu rumh-uvxiubj, jezj zmm nub zgu tguzjui uqazm, jezj jeud zgu ubiolui yd jeuxg Tguzjog lxje tugjzxb abzmxubzymu Gxkejr, jezj znobk jeuru zgu Mxhu, Mxyugjd zbi jeu wagraxj oh Ezwwxburr.--Jezj jo rutagu jeuru gxkejr, Kovugbnubjr zgu xbrjxjajui znobk Nub, iugxvxbk jeuxg sarj wolugr hgon jeu tobrubj oh jeu kovugbui, --Jezj leubuvug zbd Hogn oh Kovugbnubj yutonur iurjgatjxvu oh jeuru ubir, xj xr jeu Gxkej oh jeu Wuowmu jo zmjug og jo zyomxre xj, zbi jo xbrjxjaju bul Kovugbnubj, mzdxbk xjr hoabizjxob ob rate wgxbtxwmur zbi ogkzbxfxbk xjr wolugr xb rate hogn, zr jo jeun rezmm ruun norj mxpumd jo uhhutj jeuxg Rzhujd zbi Ezwwxburr. Wgaiubtu, xbiuui, lxmm ixtjzju jezj Kovugbnubjr mobk urjzymxreui reoami boj yu tezbkui hog mxkej zbi jgzbrxubj tzarur; zbi zttogixbkmd zmm ucwugxubtu ezje reulb, jezj nzbpxbi zgu nogu ixrworui jo rahhug, lexmu uvxmr zgu rahhugzymu, jezb jo gxkej jeunrumvur yd zyomxrexbk jeu hognr jo lexte jeud zgu zttarjonui. Yaj leub z mobk jgzxb oh zyarur zbi aragwzjxobr, wagraxbk xbvzgxzymd jeu rznu Oysutj uvxbtur z iurxkb jo guiatu jeun abiug zyromaju Iurwojxrn, xj xr jeuxg gxkej, xj xr jeuxg iajd, jo jegol ohh rate Kovugbnubj, zbi jo wgovxiu bul Kazgir hog jeuxg hajagu rutagxjd.--Rate ezr yuub jeu wzjxubj rahhugzbtu oh jeuru Tomobxur; zbi rate xr bol jeu buturrxjd lexte tobrjgzxbr jeun jo zmjug jeuxg hognug Rdrjunr oh Kovugbnubj. Jeu exrjogd oh jeu wgurubj Pxbk oh Kguzj Ygxjzxb xr z exrjogd oh guwuzjui xbsagxur zbi aragwzjxobr, zmm ezvxbk xb ixgutj oysutj jeu urjzymxrenubj oh zb zyromaju Jdgzbbd ovug jeuru Rjzjur. Jo wgovu jexr, muj Hztjr yu raynxjjui jo z tzbixi logmi.

Eu ezr guharui exr Zrrubj jo Mzlr, jeu norj leomuronu zbi buturrzgd hog jeu waymxt kooi.

Eu ezr hogyxiiub exr Kovugbogr jo wzrr Mzlr oh xnnuixzju zbi wgurrxbk xnwogjzbtu, abmurr rarwubiui xb jeuxg owugzjxob jxmm exr Zrrubj reoami yu oyjzxbui; zbi leub ro rarwubiui, eu ezr ajjugmd bukmutjui jo zjjubi jo jeun.

Eu ezr guharui jo wzrr ojeug Mzlr hog jeu zttonnoizjxob oh mzgku ixrjgxtjr oh wuowmu, abmurr jeoru wuowmu loami gumxbqaxre jeu gxkej oh Guwgurubjzjxob xb jeu Mukxrmzjagu, z gxkej xburjxnzymu jo jeun zbi hognxizymu jo jdgzbjr obmd.

Eu ezr tzmmui jokujeug mukxrmzjxvu yoixur zj wmztur abarazm, abtonhogjzymu, zbi ixrjzbj hgon jeu iuworxjogd oh jeuxg waymxt Gutogir, hog jeu romu wagworu oh hzjxkaxbk jeun xbjo tonwmxzbtu lxje exr nuzragur.

Eu ezr ixrromvui Guwgurubjzjxvu Eoarur guwuzjuimd, hog owworxbk lxje nzbmd hxgnburr exr xbvzrxobr ob jeu gxkejr oh jeu wuowmu.

Eu ezr guharui hog z mobk jxnu, zhjug rate ixrromajxobr, jo tzaru ojeugr jo yu umutjui; leuguyd jeu Mukxrmzjxvu wolugr, xbtzwzymu oh Zbbxexmzjxob, ezvu gujagbui jo jeu Wuowmu zj mzgku hog jeuxg ucugtxru; jeu Rjzju gunzxbxbk xb jeu nuzb jxnu ucworui jo zmm jeu izbkugr oh xbvzrxob hgon lxjeoaj, zbi tobvamrxobr lxjexb.

Eu ezr ubiuzvoagui jo wguvubj jeu wowamzjxob oh jeuru Rjzjur; hog jezj wagworu oyrjgatjxbk jeu Mzlr hog Bzjagzmxfzjxob oh Hoguxkbugr; guharxbk jo wzrr ojeugr jo ubtoagzku jeuxg nxkgzjxobr exjeug, zbi gzxrxbk jeu tobixjxobr oh bul Zwwgowgxzjxobr oh Mzbir.

Eu ezr oyrjgatjui jeu Zinxbxrjgzjxob oh Sarjxtu, yd guharxbk exr Zrrubj jo Mzlr hog urjzymxrexbk Saixtxzgd wolugr.

Eu ezr nziu Saikur iuwubiubj ob exr Lxmm zmobu, hog jeu jubagu oh jeuxg ohhxtur, zbi jeu znoabj zbi wzdnubj oh jeuxg rzmzgxur.

Eu ezr ugutjui z namjxjaiu oh Bul Ohhxtur, zbi rubj exjeug rlzgnr oh Ohhxtugr jo ezggzrr oag wuowmu, zbi uzj oaj jeuxg rayrjzbtu.

Eu ezr puwj znobk ar, xb jxnur oh wuztu, Rjzbixbk Zgnxur lxjeoaj jeu Tobrubj oh oag mukxrmzjagur.

Eu ezr zhhutjui jo gubiug jeu Nxmxjzgd xbiuwubiubj oh zbi rawugxog jo jeu Txvxm wolug.

Eu ezr tonyxbui lxje ojeugr jo raysutj ar jo z sagxrixtjxob hoguxkb jo oag tobrjxjajxob, zbi abztpbolmuikui yd oag mzlr; kxvxbk exr Zrrubj jo jeuxg Ztjr oh wgujubiui Mukxrmzjxob:

Hog Qazgjugxbk mzgku yoixur oh zgnui jgoowr znobk ar:

Hog wgojutjxbk jeun, yd z notp Jgxzm, hgon wabxrenubj hog zbd Nagiugr lexte jeud reoami tonnxj ob jeu Xbezyxjzbjr oh jeuru Rjzjur:

Hog tajjxbk ohh oag Jgziu lxje zmm wzgjr oh jeu logmi:

Hog xnworxbk Jzcur ob ar lxjeoaj oag Tobrubj:

Hog iuwgxvxbk ar xb nzbd tzrur, oh jeu yubuhxjr oh Jgxzm yd Sagd:

Hog jgzbrwogjxbk ar yudobi Ruzr jo yu jgxui hog wgujubiui ohhubtur

Hog zyomxrexbk jeu hguu Rdrjun oh Ubkmxre Mzlr xb z buxkeyoagxbk Wgovxbtu, urjzymxrexbk jeuguxb zb Zgyxjgzgd kovugbnubj, zbi ubmzgkxbk xjr Yoabizgxur ro zr jo gubiug xj zj obtu zb ucznwmu zbi hxj xbrjganubj hog xbjgoiatxbk jeu rznu zyromaju gamu xbjo jeuru Tomobxur:

Hog jzpxbk zlzd oag Tezgjugr, zyomxrexbk oag norj vzmazymu Mzlr, zbi zmjugxbk habiznubjzmmd jeu Hognr oh oag Kovugbnubjr:

Hog rarwubixbk oag olb Mukxrmzjagur, zbi iutmzgxbk jeunrumvur xbvurjui lxje wolug jo mukxrmzju hog ar xb zmm tzrur lezjrouvug.

Eu ezr zyixtzjui Kovugbnubj eugu, yd iutmzgxbk ar oaj oh exr Wgojutjxob zbi lzkxbk Lzg zkzxbrj ar.

Eu ezr wmabiugui oag ruzr, gzvzkui oag Tozrjr, yagbj oag jolbr, zbi iurjgodui jeu mxvur oh oag wuowmu.

Eu xr zj jexr jxnu jgzbrwogjxbk mzgku Zgnxur oh hoguxkb Nugtubzgxur jo tonwmuzj jeu logpr oh iuzje, iuromzjxob zbi jdgzbbd, zmguzid yukab lxje txgtanrjzbtur oh Tgaumjd & wughxid rtzgtumd wzgzmmumui xb jeu norj yzgyzgoar zkur, zbi jojzmmd ablogjed jeu Euzi oh z txvxmxfui bzjxob.

Eu ezr tobrjgzxbui oag hummol Txjxfubr jzpub Tzwjxvu ob jeu exke Ruzr jo yuzg Zgnr zkzxbrj jeuxg Toabjgd, jo yutonu jeu ucutajxobugr oh jeuxg hgxubir zbi Ygujegub, og jo hzmm jeunrumvur yd jeuxg Ezbir.

Eu ezr uctxjui ionurjxt xbraggutjxobr znobkrj ar, zbi ezr ubiuzvoagui jo ygxbk ob jeu xbezyxjzbjr oh oag hgobjxugr, jeu nugtxmurr Xbixzb Rzvzkur, leoru pbolb gamu oh lzghzgu, xr zb abixrjxbkaxreui iurjgatjxob oh zmm zkur, rucur zbi tobixjxobr.

Xb uvugd rjzku oh jeuru Owwgurrxobr Lu ezvu Wujxjxobui hog Guigurr xb jeu norj eanymu jugnr: Oag guwuzjui Wujxjxobr ezvu yuub zbrlugui obmd yd guwuzjui xbsagd. Z Wgxbtu leoru tezgztjug xr jear nzgpui yd uvugd ztj lexte nzd iuhxbu z Jdgzbj, xr abhxj jo yu jeu gamug oh z hguu wuowmu.

Bog ezvu Lu yuub lzbjxbk xb zjjubjxobr jo oag Ygxjjxre ygujegub. Lu ezvu lzgbui jeun hgon jxnu jo jxnu oh zjjunwjr yd jeuxg mukxrmzjagu jo ucjubi zb ablzggzbjzymu sagxrixtjxob ovug ar. Lu ezvu gunxbiui jeun oh jeu txgtanrjzbtur oh oag unxkgzjxob zbi rujjmunubj eugu. Lu ezvu zwwuzmui jo jeuxg bzjxvu sarjxtu zbi nzkbzbxnxjd, zbi lu ezvu tobsagui jeun yd jeu jxur oh oag tonnob pxbigui jo ixrzvol jeuru aragwzjxobr, lexte, loami xbuvxjzymd xbjuggawj oag tobbutjxobr zbi toggurwobiubtu. Jeud joo ezvu yuub iuzh jo jeu voxtu oh sarjxtu zbi oh tobrzbkaxbxjd. Lu narj, jeuguhogu, ztqaxurtu xb jeu buturrxjd, lexte iuboabtur oag Ruwzgzjxob, zbi eomi jeun, zr lu eomi jeu gurj oh nzbpxbi, Ubunxur xb Lzg, xb Wuztu Hgxubir.

Lu, jeuguhogu, jeu Guwgurubjzjxvur oh jeu Abxjui Rjzjur oh Znugxtz, xb Kubugzm Tobkgurr, Zrrunymui, zwwuzmxbk jo jeu Rawgunu Saiku oh jeu logmi hog jeu gutjxjaiu oh oag xbjubjxobr, io, xb jeu Bznu, zbi yd Zajeogxjd oh jeu kooi Wuowmu oh jeuru Tomobxur, romunbmd waymxre zbi iutmzgu, Jezj jeuru Abxjui Tomobxur zgu, zbi oh Gxkej oakej jo yu Hguu zbi Xbiuwubiubj Rjzjur; jezj jeud zgu Zyromvui hgon zmm Zmmukxzbtu jo jeu Ygxjxre Tgolb, zbi jezj zmm womxjxtzm tobbutjxob yujluub jeun zbi jeu Rjzju oh Kguzj Ygxjzxb, xr zbi oakej jo yu jojzmmd ixrromvui; zbi jezj zr Hguu zbi Xbiuwubiubj Rjzjur, jeud ezvu hamm Wolug jo muvd Lzg, tobtmaiu Wuztu, tobjgztj Zmmxzbtur, urjzymxre Tonnugtu, zbi jo io zmm ojeug Ztjr zbi Jexbkr lexte Xbiuwubiubj Rjzjur nzd oh gxkej io. Zbi hog jeu rawwogj oh jexr Iutmzgzjxob, lxje z hxgn gumxzbtu ob jeu wgojutjxob oh ixvxbu Wgovxiubtu, lu najazmmd wmuiku jo uzte ojeug oag Mxvur, oag Hogjabur zbi oag rztgui Eobog.

ZTX{2t060i6h18yt85h920yzh76ih8h}
```

The long ciphertext should make frequency analysis viable. Additionally, it
appears punctuation and case are preserved as stated in the hints.

There's plenty of online substitution cipher solvers online, so why spend the
effort building our own if we don't need to. Plugging the ciphertext into this
[substitution cipher solver](https://www.guballa.de/substitution-solver) yields
the plaintext.

```
The unanimous Declaration of the thirteen united States of America, When in the Course of human events, it becomes necessary for one people to dissolve the political bands which have connected them with another, and to assume among the powers of the earth, the separate and equal station to which the Laws of Nature and of Nature's God entitle them, a decent respect to the opinions of mankind requires that they should declare the causes which impel them to the separation.

We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.--That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, --That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness. Prudence, indeed, will dictate that Governments long established should not be changed for light and transient causes; and accordingly all experience hath shewn, that mankind are more disposed to suffer, while evils are sufferable, than to right themselves by abolishing the forms to which they are accustomed. But when a long train of abuses and usurpations, pursuing invariably the same Object evinces a design to reduce them under absolute Despotism, it is their right, it is their duty, to throw off such Government, and to provide new Guards for their future security.--Such has been the patient sufferance of these Colonies; and such is now the necessity which constrains them to alter their former Systems of Government. The history of the present King of Great Britain is a history of repeated injuries and usurpations, all having in direct object the establishment of an absolute Tyranny over these States. To prove this, let Facts be submitted to a candid world.

He has refused his Assent to Laws, the most wholesome and necessary for the public good.

He has forbidden his Governors to pass Laws of immediate and pressing importance, unless suspended in their operation till his Assent should be obtained; and when so suspended, he has utterly neglected to attend to them.

He has refused to pass other Laws for the accommodation of large districts of people, unless those people would relinquish the right of Representation in the Legislature, a right inestimable to them and formidable to tyrants only.

He has called together legislative bodies at places unusual, uncomfortable, and distant from the depository of their public Records, for the sole purpose of fatiguing them into compliance with his measures.

He has dissolved Representative Houses repeatedly, for opposing with manly firmness his invasions on the rights of the people.

He has refused for a long time, after such dissolutions, to cause others to be elected; whereby the Legislative powers, incapable of Annihilation, have returned to the People at large for their exercise; the State remaining in the mean time exposed to all the dangers of invasion from without, and convulsions within.

He has endeavoured to prevent the population of these States; for that purpose obstructing the Laws for Naturalization of Foreigners; refusing to pass others to encourage their migrations hither, and raising the conditions of new Appropriations of Lands.

He has obstructed the Administration of Justice, by refusing his Assent to Laws for establishing Judiciary powers.

He has made Judges dependent on his Will alone, for the tenure of their offices, and the amount and payment of their salaries.

He has erected a multitude of New Offices, and sent hither swarms of Officers to harrass our people, and eat out their substance.

He has kept among us, in times of peace, Standing Armies without the Consent of our legislatures.

He has affected to render the Military independent of and superior to the Civil power.

He has combined with others to subject us to a jurisdiction foreign to our constitution, and unacknowledged by our laws; giving his Assent to their Acts of pretended Legislation:

For Quartering large bodies of armed troops among us:

For protecting them, by a mock Trial, from punishment for any Murders which they should commit on the Inhabitants of these States:

For cutting off our Trade with all parts of the world:

For imposing Taxes on us without our Consent:

For depriving us in many cases, of the benefits of Trial by Jury:

For transporting us beyond Seas to be tried for pretended offences

For abolishing the free System of English Laws in a neighbouring Province, establishing therein an Arbitrary government, and enlarging its Boundaries so as to render it at once an example and fit instrument for introducing the same absolute rule into these Colonies:

For taking away our Charters, abolishing our most valuable Laws, and altering fundamentally the Forms of our Governments:

For suspending our own Legislatures, and declaring themselves invested with power to legislate for us in all cases whatsoever.

He has abdicated Government here, by declaring us out of his Protection and waging War against us.

He has plundered our seas, ravaged our Coasts, burnt our towns, and destroyed the lives of our people.

He is at this time transporting large Armies of foreign Mercenaries to compleat the works of death, desolation and tyranny, already begun with circumstances of Cruelty & perfidy scarcely paralleled in the most barbarous ages, and totally unworthy the Head of a civilized nation.

He has constrained our fellow Citizens taken Captive on the high Seas to bear Arms against their Country, to become the executioners of their friends and Brethren, or to fall themselves by their Hands.

He has excited domestic insurrections amongst us, and has endeavoured to bring on the inhabitants of our frontiers, the merciless Indian Savages, whose known rule of warfare, is an undistinguished destruction of all ages, sexes and conditions.

In every stage of these Oppressions We have Petitioned for Redress in the most humble terms: Our repeated Petitions have been answered only by repeated injury. A Prince whose character is thus marked by every act which may define a Tyrant, is unfit to be the ruler of a free people.

Nor have We been wanting in attentions to our Brittish brethren. We have warned them from time to time of attempts by their legislature to extend an unwarrantable jurisdiction over us. We have reminded them of the circumstances of our emigration and settlement here. We have appealed to their native justice and magnanimity, and we have conjured them by the ties of our common kindred to disavow these usurpations, which, would inevitably interrupt our connections and correspondence. They too have been deaf to the voice of justice and of consanguinity. We must, therefore, acquiesce in the necessity, which denounces our Separation, and hold them, as we hold the rest of mankind, Enemies in War, in Peace Friends.

We, therefore, the Representatives of the United States of America, in General Congress, Assembled, appealing to the Supreme Judge of the world for the rectitude of our intentions, do, in the Name, and by Authority of the good People of these Colonies, solemnly publish and declare, That these United Colonies are, and of Right ought to be Free and Independent States; that they are Absolved from all Allegiance to the British Crown, and that all political connection between them and the State of Great Britain, is and ought to be totally dissolved; and that as Free and Independent States, they have full Power to levy War, conclude Peace, contract Alliances, establish Commerce, and to do all other Acts and Things which Independent States may of right do. And for the support of this Declaration, with a firm reliance on the protection of divine Providence, we mutually pledge to each other our Lives, our Fortunes and our sacred Honor.

ACI{2c060d6f18bc85f920baf76df8f}
```
