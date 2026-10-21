package com.packetsentry.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;

import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

/**
 * 会换行的 FlowLayout。
 *
 * <h3>为什么需要它</h3>
 *
 * 工具栏原来用 {@code BoxLayout(X_AXIS)}。它在【首选宽度总和 > 可用宽度】时
 * <b>不会换行，而是把每个组件压到 minimumSize</b>。我们给按钮的 minimum
 * 宽度是 0，于是按钮被压到 0 宽：文字互相重叠、标签被裁掉一半、
 * 下拉框的编辑区和箭头叠在一起 —— 用户截图里那些"黑块 + 1∨"就是这么来的。
 *
 * <p>高 DPI 环境下尤其明显：字体变大 → 首选宽度变大 → 更容易超宽。
 *
 * <p>本类把超宽的处理方式从「压扁」改成「折行」：宽度够就一行，
 * 不够就自动折成多行，控件始终保持自己的首选尺寸。
 *
 * <h3>实现要点</h3>
 * {@link FlowLayout} 自己的 {@code preferredLayoutSize} 不计算折行后的高度，
 * 所以这里重写它：先假定一个极宽的容器把每一行排出来，再按目标宽度折行，
 * 累加出真实需要的高度。这样外层 {@code BorderLayout.NORTH} 才会跟着变高。
 */
public class WrapLayout extends FlowLayout {

    public WrapLayout(int align, int hgap, int vgap) {
        super(align, hgap, vgap);
    }

    @Override
    public Dimension preferredLayoutSize(Container target) {
        return layoutSize(target, true);
    }

    @Override
    public Dimension minimumLayoutSize(Container target) {
        Dimension d = layoutSize(target, false);
        // 减掉一个 hgap：FlowLayout 的惯例
        d.width -= (getHgap() + 1);
        return d;
    }

    private Dimension layoutSize(Container target, boolean preferred) {
        synchronized (target.getTreeLock()) {
            int targetWidth = target.getSize().width;

            // 首次布局时宽度还是 0 —— 先当"无限宽"处理，排成一行；
            // 等容器拿到真实宽度后 revalidate() 会重新算。
            if (targetWidth <= 0) {
                targetWidth = Integer.MAX_VALUE;
            }

            int hgap = getHgap();
            int vgap = getVgap();
            Insets insets = target.getInsets();
            int horizontalInsetsAndGap = insets.left + insets.right + hgap * 2;
            int maxWidth = targetWidth - horizontalInsetsAndGap;

            Dimension dim = new Dimension(0, 0);
            int rowWidth = 0;
            int rowHeight = 0;

            int members = target.getComponentCount();
            for (int i = 0; i < members; i++) {
                Component m = target.getComponent(i);
                if (!m.isVisible()) {
                    continue;
                }
                Dimension d = preferred ? m.getPreferredSize() : m.getMinimumSize();

                // 放不下就换行
                if (rowWidth + d.width > maxWidth) {
                    addRow(dim, rowWidth, rowHeight);
                    rowWidth = 0;
                    rowHeight = 0;
                }
                if (rowWidth != 0) {
                    rowWidth += hgap;
                }
                rowWidth += d.width;
                rowHeight = Math.max(rowHeight, d.height);
            }
            addRow(dim, rowWidth, rowHeight);

            dim.width += horizontalInsetsAndGap;
            dim.height += insets.top + insets.bottom + vgap * 2;

            // 放在滚动容器里时，别把滚动条宽度也算进去，否则会一直闪
            Container scrollPane = SwingUtilities.getAncestorOfClass(JScrollPane.class, target);
            if (scrollPane != null && target.isValid()) {
                dim.width -= (hgap + 1);
            }
            return dim;
        }
    }

    private void addRow(Dimension dim, int rowWidth, int rowHeight) {
        dim.width = Math.max(dim.width, rowWidth);
        if (dim.height > 0) {
            dim.height += getVgap();
        }
        dim.height += rowHeight;
    }
}
